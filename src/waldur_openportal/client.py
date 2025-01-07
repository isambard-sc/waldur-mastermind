import logging
import os

from . import op as openportal


from waldur_openportal.base import BaseBatchClient
from waldur_slurm.structures import Account

from .models import Allocation


logger = logging.getLogger(__name__)


class OpenPortalRunner:
    """
    This class is actually responsible for running OpenPortal commands
    """
    def __init__(self):
        # make sure that the OpenPortal config is loaded
        if not openportal.have_openportal:
            raise openportal.OpenPortalError("OpenPortal is not available")

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
            raise openportal.OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

        if not config_file:
            raise openportal.OpenPortalError("OPENPORTAL_CONFIG environment variable not set")

        try:
            # this isn't thread-safe - we should make it thread-save
            # in the OpenPortal python layer
            openportal.load_config(config_file)
        except Exception as e:
            raise openportal.OpenPortalError(f"Failed to load OpenPortal config from '{config_file}': {e}")

    def health(self):
        if not openportal.have_openportal:
            raise openportal.OpenPortalError("OpenPortal is not available")

        try:
            health = openportal.health()
        except Exception as e:
            raise openportal.OpenPortalError(f"Failed to get OpenPortal health: {e}")

        if not health.is_healthy():
            logger.error(f"OpenPortal is not healthy: {health}")
            raise openportal.OpenPortalError(f"OpenPortal is not healthy: {health}")

    def get(self, uid):
        """
        Return the OpenPortal job with the specified UID
        """
        if not openportal.have_openportal:
            raise openportal.OpenPortalError(f"OpenPortal is not available - cannot get job with UID '{uid}'")

        try:
            job = openportal.get(str(uid))
        except Exception as e:
            raise openportal.OpenPortalError(f"Failed to get job with UID '{uid}': {e}")

        return job

    def run(self, command):
        """
        Run the OpenPortal command 'command' and return the OpenPortal
        job that was created. Raises an OpenPortalException if anything
        goes wrong
        """
        if not openportal.have_openportal:
            raise openportal.OpenPortalError(f"OpenPortal is not available - cannot run '{command}'")

        try:
            job = openportal.run(command, 100)
        except Exception as e:
            raise openportal.OpenPortalError(f"Failed to run '{command}': {e}")

        return job


class OpenPortalClient(BaseBatchClient):
    """
    This class implements Python client for OpenPortal.
    See also: https://github.com/isambard-sc/openportal
    """
    def __init__(self, instance_name):
        self._runner = OpenPortalRunner()
        self._destination = openportal.Destination(instance_name)

        logger.info(f"Created OpenPortal client for instance {self._destination}")

    def health(self) -> openportal.Health:
        """
        Check the health of the OpenPortal system
        """
        self._runner.health()

    def destination(self) -> openportal.Destination:
        """
        Return the destination that identifies the instance that
        is being managed by this client
        """
        return self._destination

    def add_user(self, shortname: str, project: openportal.ProjectIdentifier) -> openportal.UserMapping:
        """
        Tell OpenPortal to add the specified short (unix) name to the project.
        The username should be unique on the caller
        side. OpenPortal will derive its own internal username for this user,
        based on the passed username and project, which will be returned by
        this method once the user has been added
        """
        if not isinstance(project, openportal.ProjectIdentifier):
            project = openportal.ProjectIdentifier(project)

        if (not shortname) or (not shortname.strip()):
            raise openportal.OpenPortalError(f"Invalid empty username '{shortname}'")

        user = openportal.UserIdentifier(f"{shortname}.{project}")

        mapping = self.run(f"{self.destination()} add_user {user}")

        logger.info(f"Added OpenPortal user to project {project} with mapping {mapping}")

        return mapping

    def delete_user(self, user: openportal.UserIdentifier) -> None:
        """
        Remove the OpenPortal user with specified UserIdentifier
        """
        if not isinstance(user, openportal.UserIdentifier):
            user = openportal.UserIdentifier(user)

        self.run(f"{self.destination()} remove_user {user}")

        logger.info(f"Deleted OpenPortal user '{user}'")

    def add_project(self, project: openportal.ProjectIdentifier) -> openportal.ProjectMapping:
        """
        Tell OpenPortal to create a project with the specified name.
        This name should be unique on the caller side. OpenPortal will
        derive a unique internal name for this project based on that
        name, and will create it, and return the internal name that
        was used (which we will call the `op_project_name`)
        """
        if not isinstance(project, openportal.ProjectIdentifier):
            project = openportal.ProjectIdentifier(project)

        mapping = self.run(f"{self.destination()} add_project {project}")

        logger.info(f"Created OpenPortal project {project} with mapping {mapping}")

        return mapping

    def delete_project(self, project: openportal.ProjectIdentifier):
        """
        Delete the project with the specified name.
        """
        if not isinstance(project, openportal.ProjectIdentifier):
            project = openportal.ProjectIdentifier(project)

        self.run(f"{self.destination()} remove_project {project}")

    def set_resource_limits(self, account, quotas):
        logger.info(f"OpenPortal NoOp - Setting resource limits for account '{account}' to '{quotas}'")

    def get_usage_report(self, accounts):
        logger.info(f"OpenPortal NoOp - Getting usage report for accounts '{accounts}'")

    def get_resource_limits(self, account):
        logger.info(f"OpenPortal NoOp - Getting resource limits for account '{account}'")

    def get_users(self, project: openportal.ProjectIdentifier) -> list[openportal.UserMapping]:
        return self.run(f"{self.destination()} get_users {project}")

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
            raise openportal.OpenPortalError(f"Job '{command}' failed: {op_job.error_message}")
        else:
            logger.info(f"Job finished: {op_job}")
            return op_job.result


    ### Required methods to override from BaseBatchClient

    def list_accounts(self):
        projects = self.run(f"{self.destination()} get_projects")

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
        self.delete_project(name)

    def get_account(self, name):
        # Again, we need to map from the project name to the internal name
        # for the project
        logger.warning("OpenPortal NoOp - Getting account is not implemented")

    def create_association(self, username, account, default_account=""):
        # Again, we need to map to internal names...
        logger.warning("OpenPortal NoOp - Creating association is not implemented")

    def delete_association(self, username, account):
        # Again, we need to map to internal names...
        logger.warning("OpenPortal NoOp - Deleting association is not implemented")

    def get_association(self, user, account):
        # Again, we need to map to internal names...
        logger.warning("OpenPortal NoOp - Getting association is not implemented")
