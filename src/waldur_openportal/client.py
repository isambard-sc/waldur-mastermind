import logging

try:
    import openportal
    import os
    have_openportal = True
except ImportError:
    have_openportal = False


from waldur_openportal.base import BaseBatchClient, BatchError
from waldur_slurm.structures import Account

from .models import Allocation


class OpenPortalError(BatchError):
    pass


logger = logging.getLogger(__name__)


class OpenPortalRunner:
    """
    This class is actually responsible for running OpenPortal commands
    """
    def __init__(self):
        # make sure that the OpenPortal config is loaded
        if not have_openportal:
            raise OpenPortalError("OpenPortal is not available")

        if not openportal.is_config_loaded():
            self.load_config()

    def load_config(self):
        """
        Load the OpenPortal configuration from the file specified
        in the OPENPORTAL_CONFIG environment variable. Raises an
        OpenPortalException if the environment variable is not set
        or if the config file cannot be loaded
        """
        # the name of the config file is held in the
        # OPENPORTAL_CONFIG environment variable
        try:
            config_file = os.environ.get("OPENPORTAL_CONFIG")
        except KeyError:
            raise OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

        if not config_file:
            raise OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

        try:
            # this isn't thread-safe - we should make it thread-save
            # in the OpenPortal python layer
            openportal.load_config(config_file)
        except Exception as e:
            raise OpenPortalError(f"Failed to load OpenPortal config from '{config_file}': {e}")

    def health(self):
        if not have_openportal:
            raise OpenPortalError("OpenPortal is not available")

        try:
            health = openportal.health()
        except Exception as e:
            raise OpenPortalError(f"Failed to get OpenPortal health: {e}")

        if not health.is_healthy():
            logger.error(f"OpenPortal is not healthy: {health}")
            raise OpenPortalError(f"OpenPortal is not healthy: {health}")

    def get(self, uid):
        """
        Return the OpenPortal job with the specified UID
        """
        if not have_openportal:
            raise OpenPortalError(f"OpenPortal is not available - cannot get job with UID '{uid}'")

        try:
            job = openportal.get(str(uid))
        except Exception as e:
            raise OpenPortalError(f"Failed to get job with UID '{uid}': {e}")

        return job

    def run(self, command):
        """
        Run the OpenPortal command 'command' and return the OpenPortal
        job that was created. Raises an OpenPortalException if anything
        goes wrong
        """
        if not have_openportal:
            raise OpenPortalError(f"OpenPortal is not available - cannot run '{command}'")

        try:
            job = openportal.run(command, 100)
        except Exception as e:
            raise OpenPortalError(f"Failed to run '{command}': {e}")

        return job


class OpenPortalClient(BaseBatchClient):
    """
    This class implements Python client for OpenPortal.
    See also: https://github.com/isambard-sc/openportal
    """
    def __init__(self, instance_name):
        self._runner = OpenPortalRunner()

        instance_name = instance_name.lower().strip()

        if " " in instance_name:
            raise OpenPortalError("Instance name cannot contain spaces")

        if "." not in instance_name:
            raise OpenPortalError("Instance name must contain a period")

        if len(instance_name) < 3:
            raise OpenPortalError("Instance name must be at least 3 characters long")

        self._instance_name = instance_name
        self._portal_name = instance_name.split(".")[0]

        if len(self._portal_name) < 1:
            raise OpenPortalError("Portal name must be at least 1 character long")

        logger.info(f"Created OpenPortal client with instance name '{instance_name}'")

    def health(self):
        """
        Check the health of the OpenPortal system
        """
        self._runner.health()

    def instance_name(self):
        """
        Return the full path name for the agent instance that
        is being used by this client
        """
        return self._instance_name

    def portal_name(self):
        """
        Return the name of the portal that is being used by this client
        """
        return self._portal_name

    def _sanitise_project_name(self, name):
        name = name.lower().strip().replace(" ", "_").replace(".", "_")
        return f"{name}.{self.portal_name()}"

    def _sanitise_op_project_name(self, name):
        name = name.lower().strip().replace(" ", "_")

        if not name.endswith(f".{self.portal_name()}"):
            raise OpenPortalError(f"Project name '{name}' does not end with portal name '{self.portal_name()}'")

        if len(name) <= len(self.portal_name()) + 2:
            raise OpenPortalError(f"Project name '{name}' is too short")

        return name

    def _sanitise_user_name(self, name):
        name = name.lower().strip().replace(" ", "_").replace(".", "_")
        return name

    def _sanitise_op_user_name(self, name):
        name = name.lower().strip().replace(" ", "_")

        if not name.endswith(f".{self.portal_name()}"):
            raise OpenPortalError(f"User name '{name}' does not end with portal name '{self.portal_name()}'")

        if name.count(".") != 2:
            raise OpenPortalError(f"User name '{name}' does not contain exactly 2 periods")

        if len(name) <= len(self.portal_name()) + 3:
            raise OpenPortalError(f"User name '{name}' is too short")

        return name

    def add_user(self, name, op_project_name):
        """
        Tell OpenPortal to add the specified name to the project with the
        specified project_id. The username should be unique on the caller
        side. OpenPortal will derive its own internal username for this user,
        based on the passed username, which will be returned by this method
        once the user has been added (which we will call the op_user_name)
        """
        username = self._sanitise_user_name(name)
        op_project_name = self._sanitise_op_project_name(op_project_name)

        op_user_name = str(self.run(f"{self.instance_name()} add_user {username}.{op_project_name}").user)

        logger.info(f"Added OpenPortal user '{username}' to project '{op_project_name}' with internal name '{op_user_name}'")

        return self._sanitise_op_user_name(op_user_name)

    def delete_user(self, op_user_name):
        """
        Remove the OpenPortal user with specified op_user_name
        """
        op_user_name = self._sanitise_op_user_name(op_user_name)

        self.run(f"{self.instance_name()} remove_user {self._sanitise_op_user_name(op_user_name)}")

        logger.info(f"Deleted OpenPortal user '{op_user_name}'")

    def add_project(self, name):
        """
        Tell OpenPortal to create a project with the specified name.
        This name should be unique on the caller side. OpenPortal will
        derive a unique internal name for this project based on that
        name, and will create it, and return the internal name that
        was used (which we will call the `op_project_name`)
        """
        project_name = self._sanitise_project_name(name)

        op_project_name = str(self.run(f"{self.instance_name()} add_project {project_name}").project)

        logger.info(f"Created OpenPortal project '{project_name}' with internal name '{op_project_name}'")

        return self._sanitise_op_project_name(op_project_name)

    def delete_project(self, op_project_name):
        """
        Delete the project with the specified `op_project_name`. This should be
        the internal name used for the project
        """
        op_project_name = self._sanitise_op_project_name(op_project_name)

        self.run(f"{self.instance_name()} remove_project {self._sanitise_op_project_name(op_project_name)}")

    def set_resource_limits(self, account, quotas):
        logger.info(f"Setting resource limits for account '{account}' to '{quotas}'")
        # raise NotImplementedError("set_resource_limits is not implemented")

    def get_usage_report(self, accounts):
        raise NotImplementedError("get_usage_report is not implemented")

    def get_resource_limits(self, account):
        raise NotImplementedError("get_usage_report is not implemented")

    def get_users(self, op_project_name):
        op_project_name = self._sanitise_op_project_name(op_project_name)
        users = self.run(f"{self.instance_name()} get_users {op_project_name}")
        logger.info(f"Got users for project '{op_project_name}': {users}")

        return []

    def run(self, command):
        """
        Run the passed command and await the result
        """
        logger.info(f"Running command '{command}'")
        op_job = self._runner.run(command)

        while not op_job.wait(1000):
            logger.info(f"Job {command} is still running...")

        if op_job.is_error:
            logger.error(f"Job {command} has failed: {op_job.error_message}")
            raise OpenPortalError(f"Job '{command}' failed: {op_job.error_message}")
        else:
            logger.info(f"Job finished: {op_job}")
            return op_job.result


    ### Required methods to override from BaseBatchClient

    def list_accounts(self):
        projects = self.run(f"{self.instance_name()} get_projects")

        # parse the above into a list of Account objects
        logger.info(f"Got projects: {projects}")

        return [Account(name=project, description="", organization="") for project in projects]

    def create_account(self, name, description, organization, parent_name=None):
        logger.info(f"Creating account '{name}' with description '{description}' and organization '{organization}'")

        if parent_name is not None:
            logger.warning(f"Ignoring parent_name '{parent_name}' as OpenPortal does not support account hierarchies")

        return self.add_project(name)

    def delete_account(self, name):
        logger.info(f"Deleting account '{name}'")

        # note that we probably want the caller to have already found the
        # internal name for the project, as we don't want to have to do that
        # here
        raise NotImplementedError("delete_account is not implemented")

    def get_account(self, name):
        # Again, we need to map from the project name to the internal name
        # for the project
        raise NotImplementedError("get_account is not implemented")

    def create_association(self, username, account, default_account=""):
        # Again, we need to map to internal names...
        raise NotImplementedError("create_association is not implemented")

    def delete_association(self, username, account):
        # Again, we need to map to internal names...
        raise NotImplementedError("delete_association is not implemented")

    def get_association(self, user, account):
        # Again, we need to map to internal names...
        raise NotImplementedError("get_association is not implemented")
