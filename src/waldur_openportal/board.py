import logging
import os

from . import op as openportal

logger = logging.getLogger(__name__)


class OpenPortalBoard:
    """
    This class implements the OpenPortal job board interface,
    letting you get jobs, process them, and send back results.

    See also: https://github.com/isambard-sc/openportal
    """

    def __init__(self):
        # make sure that the OpenPortal config is loaded
        if not openportal.have_openportal():
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
            raise openportal.OpenPortalError(
                "OPENPORTAL_CONFIG environment variable not set"
            )

        if not config_file:
            raise openportal.OpenPortalError(
                "OPENPORTAL_CONFIG environment variable not set"
            )

        try:
            # this isn't thread-safe - we should make it thread-save
            # in the OpenPortal python layer
            openportal.load_config(config_file)
        except Exception as e:
            raise openportal.OpenPortalError(
                f"Failed to load OpenPortal config from '{config_file}': {e}"
            )

    def health(self):
        if not openportal.have_openportal():
            raise openportal.OpenPortalError("OpenPortal is not available")

        try:
            health = openportal.health()
        except Exception as e:
            raise openportal.OpenPortalError(f"Failed to get OpenPortal health: {e}")

        if not health.is_healthy():
            logger.error(f"OpenPortal is not healthy: {health}")
            raise openportal.OpenPortalError(f"OpenPortal is not healthy: {health}")

    def fetch_job(self, job_id: str) -> openportal.Job:
        """
        Fetch the OpenPortal job with the specified job_id
        """
        if not openportal.have_openportal():
            raise openportal.OpenPortalError(
                f"OpenPortal is not available - cannot fetch job with ID '{job_id}'"
            )

        try:
            job = openportal.fetch_job(str(job_id))
        except Exception as e:
            raise openportal.OpenPortalError(
                f"Failed to fetch job with ID '{job_id}': {e}"
            )

        return job

    def create_project(
        self, project: openportal.ProjectIdentifier, details: openportal.ProjectDetails
    ) -> openportal.ProjectMapping:
        """
        Create a project in OpenPortal with the given identifier and details.
        This returns the mapping from the identifier in the requesting portal
        to the OpenPortal project identifier used internally.
        """
        logger.info(f"Creating project {project} with details {details}")

        if not isinstance(project, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(f"Invalid project identifier: {project}")

        if not isinstance(details, openportal.ProjectDetails):
            raise openportal.OpenPortalError(f"Invalid project details: {details}")

        return openportal.ProjectMapping(f"{project}:u5a")

    def update_project(
        self, project: openportal.ProjectIdentifier, details: openportal.ProjectDetails
    ) -> openportal.ProjectMapping:
        """
        Update a project in OpenPortal with the given identifier and details.
        This returns the mapping from the identifier in the requesting portal
        to the OpenPortal project identifier used internally.
        """
        logger.info(f"Updating project {project} with details {details}")

        if not isinstance(project, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(f"Invalid project identifier: {project}")

        if not isinstance(details, openportal.ProjectDetails):
            raise openportal.OpenPortalError(f"Invalid project details: {details}")

        return openportal.ProjectMapping(f"{project}:u5a")

    def get_project(
        self, project: openportal.ProjectIdentifier
    ) -> openportal.ProjectDetails:
        """
        Get a project from OpenPortal with the given identifier.
        This returns the details of the project, e.g. its name,
        description, members etc.
        """
        logger.info(f"Getting project {project}")

        if not isinstance(project, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(f"Invalid project identifier: {project}")

        details = openportal.ProjectDetails("{}")

        details.name = "Project Something Something"
        details.description = "This is a test project"

        return details

    def get_project_mapping(
        self, project: openportal.ProjectIdentifier
    ) -> openportal.ProjectMapping:
        """
        Get the mapping for a project in OpenPortal with the given identifier.
        This returns the mapping from the identifier in the requesting portal
        to the OpenPortal project identifier used internally.
        """
        logger.info(f"Getting project mapping for {project}")

        if not isinstance(project, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(f"Invalid project identifier: {project}")

        return openportal.ProjectMapping(f"{project}:u5a")

    def get_usage_report(
        self,
        project: openportal.ProjectIdentifier,
        date_range: openportal.DateRange,
    ) -> openportal.UsageReport:
        """
        Get a usage report for a project in OpenPortal for the given date range.
        This returns the usage report, which contains the usage data for the project.
        """
        logger.info(
            f"Getting usage report for project {project} in date range {date_range}"
        )

        if not isinstance(project, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(f"Invalid project identifier: {project}")

        if not isinstance(date_range, openportal.DateRange):
            raise openportal.OpenPortalError(f"Invalid date range: {date_range}")

        return openportal.UsageReport(openportal.PortalIdentifier("brics"))

    def send_result(self, job: openportal.Job) -> None:
        """
        Send the result of a job back to OpenPortal.
        """
        logger.info(f"Sending result for job {job}")

        if not isinstance(job, openportal.Job):
            raise openportal.OpenPortalError(f"Invalid job: {job}")

        openportal.send_result(job)
