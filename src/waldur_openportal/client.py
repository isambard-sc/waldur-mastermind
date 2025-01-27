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

    def get(self, uid: str) -> openportal.Job:
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

    def run(self, command: str) -> openportal.Job:
        """
        Run the OpenPortal command 'command' and return the OpenPortal
        job that was created. Raises an OpenPortalError if anything
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
        if instance_name is None:
            raise openportal.OpenPortalError("Instance name cannot be None")

        self._runner = OpenPortalRunner()
        self._destination = openportal.Destination(instance_name)

    def _to_project_identifier(self, project) -> openportal.ProjectIdentifier:
        """
        Convert the passed (any) object into a ProjectIdentifier
        """
        if not isinstance(project, openportal.ProjectIdentifier):
            try:
                project = openportal.ProjectIdentifier(project)
            except Exception:
                project = openportal.ProjectIdentifier(f"{project}.{self.portal()}")

        return project

    def _to_user_identifier(self, user) -> openportal.UserIdentifier:
        """
        Convert the passed (any) object into a UserIdentifier
        """
        if not isinstance(user, openportal.UserIdentifier):
            try:
                user = openportal.UserIdentifier(user)
            except Exception:
                user = openportal.UserIdentifier(f"{user}.{self.portal()}")

        return user

    def _to_usage(self, usage) -> openportal.Usage:
        """
        Convert the passed (any) object into a Usage object
        """
        if not isinstance(usage, openportal.Usage):
            usage = openportal.Usage.parse(str(usage))

        return usage

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

    def portal(self) -> openportal.PortalIdentifier:
        """
        Return the name of the portal that holds the instance that
        is being managed by this client
        """
        try:
            return openportal.PortalIdentifier(self._destination.agents[0])
        except Exception as e:
            logger.error(f"Failed to get portal name from destination {self._destination}: {e}")
            raise openportal.OpenPortalError(f"Failed to get portal name from destination {self._destination}: {e}")

    def add_user(self, shortname: str, project: openportal.ProjectIdentifier) -> openportal.UserMapping:
        """
        Tell OpenPortal to add the specified short (unix) name to the project.
        The username should be unique on the caller
        side. OpenPortal will derive its own internal username for this user,
        based on the passed username and project, which will be returned by
        this method once the user has been added
        """
        project = self._to_project_identifier(project)

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
        user = self._to_user_identifier(user)

        self.run(f"{self.destination()} remove_user {user}")

        logger.info(f"Deleted OpenPortal user '{user}'")

    def add_project(self, project: openportal.ProjectIdentifier) -> openportal.ProjectMapping:
        """
        Tell OpenPortal to create a project with the specified name.
        This name should be unique on the caller side. OpenPortal will
        derive a unique internal name for this project based on that
        name, and will create it, and return the mapping
        """
        project = self._to_project_identifier(project)

        mapping = self.run(f"{self.destination()} add_project {project}")

        logger.info(f"Created OpenPortal project {project} with mapping {mapping}")

        return mapping

    def delete_project(self, project: openportal.ProjectIdentifier):
        """
        Delete the project with the specified name.
        """
        project = self._to_project_identifier(project)

        self.run(f"{self.destination()} remove_project {project}")

    def set_resource_limits(self, project: openportal.ProjectIdentifier, limit: openportal.Usage) -> openportal.Usage:
        """
        Set the resource usage limit for the specified project to the specified limit.
        This returns the limit that has actually been set.
        """
        project = self._to_project_identifier(project)
        usage = self._to_usage(limit)

        new_limit = self.run(f"{self.destination()} set_limit {project} {limit}")

        return new_limit

    def get_resource_limits(self, project: openportal.ProjectIdentifier) -> openportal.Usage:
        """
        Get the resource usage limit for the specified project
        """
        project = self._to_project_identifier(project)

        limit = self.run(f"{self.destination()} get_limit {project}")

        return limit

    def get_usage_report(self, project: openportal.ProjectIdentifier, date_range: openportal.DateRange):
        """
        Return the usage report for the specified project and date range
        """
        project = self._to_project_identifier(project)

        report = self.run(f"{self.destination()} get_usage_report {project} {date_range}")
        return report

    def get_users(self, project: openportal.ProjectIdentifier) -> list[openportal.UserMapping]:
        """
        Return the mappings for all users on the resource for the specified project
        """
        project = self._to_project_identifier(project)
        return self.run(f"{self.destination()} get_users {project}")

    def run(self, command: str):
        """
        Run the passed command and await the result
        """
        logger.info(f"Running command '{command}'")
        op_job = self._runner.run(command)

        while not op_job.wait(2500):
            logger.info(f"Job {command} is still running...")

        if op_job.is_error:
            logger.error(f"Job {command} has failed: {op_job.error_message}")
            raise openportal.OpenPortalError(f"Job '{command}' failed: {op_job.error_message}")
        else:
            logger.info(f"Job finished: {command} - SUCCESS")
            return op_job.result

    ### Required methods to override from BaseBatchClient

    def list_accounts(self) -> list[Account]:
        """
        Return the Account objects for all projects active on the resource
        """
        projects = self.run(f"{self.destination()} get_projects")
        return [Account(name=project, description="", organization="") for project in projects]

    def create_account(self, name: str, description: str, organization: str, parent_name: str=None) -> openportal.ProjectMapping:
        """
        Create an account with the specified name, description, organization and parent account.
        However, OpenPortal only cares about the project name, and ignores the description,
        organisation and parent name. This just creates a project with the specified name,
        returning the project mapping for that project
        """
        logger.info(f"Creating account '{name}' with description '{description}' and organization '{organization}'")

        if parent_name is not None:
            logger.warning(f"Ignoring parent_name '{parent_name}' as OpenPortal does not support account hierarchies")

        return self.add_project(name)

    def delete_account(self, name: str):
        """
        Delete the account with the specified name (the name should be the project identifier)
        """
        logger.warning(f"OpenPortal NoOp - Deleting account '{name}' is not implemented")

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
