import logging
import os

from waldur_core.structure import models as structure_models

from . import op as openportal
from . import models

logger = logging.getLogger(__name__)


class OpenPortalBoard:
    """
    This class implements the OpenPortal job board interface,
    letting you get jobs, process them, and send back results.

    See also: https://github.com/isambard-sc/openportal
    """

    def __init__(self, destination: openportal.Destination = None):
        # make sure that the OpenPortal config is loaded
        if not openportal.have_openportal():
            raise openportal.OpenPortalError("OpenPortal is not available")

        if not openportal.is_config_loaded():
            self.load_config()

        if destination is not None and isinstance(destination, openportal.Destination):
            self._destination = destination

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

    def portal(self) -> openportal.PortalIdentifier:
        """
        Return the name of the portal that represents the web portal
        connected to by the Bridge managed by this board.
        """
        try:
            return openportal.PortalIdentifier(self._destination.agents[0])
        except Exception as e:
            logger.error(
                f"Failed to get portal name from destination {self._destination}: {e}"
            )
            raise openportal.OpenPortalError(
                f"Failed to get portal name from destination {self._destination}: {e}"
            )

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

    def _verify_existing_project_details(self, managed_project: models.ManagedProject):
        """
        Verify that the existing project details match the managed project.
        If not, update the project to have the correct details
        """
        project = managed_project.project

        if project is None:
            logger.error(
                f"ManagedProject {managed_project} does not have an associated project."
            )
            return

        details = managed_project.get_details()

        if details is None:
            logger.error(
                f"ManagedProject {managed_project} does not have project details."
            )
            return

        if details.name is not None and details.name != project.name:
            project.name = details.name

        if (
            details.description is not None
            and details.description != project.description
        ):
            project.description = details.description

        if details.start_date is not None and details.start_date != project.start_date:
            project.start_date = details.start_date

        if details.end_date is not None and details.end_date != project.end_date:
            project.end_date = details.end_date

        project.save()

        if details.members is not None:
            # Check that these members are already in the project...
            # Note that we don't change roles for people who have already
            # been added to the project, or for invitations already sent
            logger.warning("Need to verify project members!")

        if details.credit is not None:
            logger.warning("Need to verify project credit!")

    def create_project(
        self,
        identifier: openportal.ProjectIdentifier,
        details: openportal.ProjectDetails,
    ) -> openportal.ProjectMapping:
        """
        Create a project in OpenPortal with the given identifier and details.
        This returns the mapping from the identifier in the requesting portal
        to the OpenPortal project identifier used internally.
        """
        logger.info(f"Creating project {identifier} with details {details}")

        if not isinstance(identifier, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(
                f"Invalid project identifier: {identifier}"
            )

        if not isinstance(details, openportal.ProjectDetails):
            raise openportal.OpenPortalError(f"Invalid project details: {details}")

        # Get (or create) the ManagedProject for the given project identifier
        try:
            managed_project = models.ManagedProject.objects.create(
                identifier=str(identifier)
            )
        except Exception:
            managed_project = models.ManagedProject.objects.filter(
                identifier=str(identifier)
            ).first()

        if not managed_project:
            logger.error(
                f"Failed to create or get ManagedProject for identifier {identifier}."
            )
            raise openportal.OpenPortalError(
                f"ManagedProject for identifier '{identifier}' could not be created or found"
            )

        if managed_project.project is not None:
            if managed_project.project.is_expired or managed_project.project.is_removed:
                # we can't make any changes to this project - return an error
                logger.error(
                    f"ManagedProject {managed_project} is expired or removed, cannot create project."
                )
                raise openportal.OpenPortalError(
                    f"ManagedProject '{managed_project}' is expired or removed, cannot create project"
                )

            # we have already created this project, so we can just return the mapping - check
            # there the project details are in agreement with the existing project
            if managed_project.details is None:
                # This is a bug
                logger.error(
                    f"Project details for {managed_project} are None, but the project already exists."
                )
                raise openportal.OpenPortalError(
                    f"Project details for {managed_project} are None, but the project already exists."
                )
            elif managed_project.details != str(details):
                logger.warning(
                    f"Project details for {managed_project} do not match the existing project details."
                )
                raise openportal.OpenPortalError(
                    f"Project details for {managed_project} do not match the existing project details."
                )

            if managed_project.local_identifier is None:
                project_info = models.ProjectInfo.objects.filter(
                    project=managed_project.project
                ).first()

                if project_info is None:
                    logger.error(
                        f"ProjectInfo for project {managed_project.project} not found."
                    )
                    raise openportal.OpenPortalError(
                        f"ProjectInfo for project '{managed_project.project}' not found"
                    )

                if project_info.shortname is None:
                    # generate the shortname now for this project
                    logger.warning(
                        f"ProjectInfo for project {managed_project.project} does not have a shortname, generating one."
                    )

                    if managed_project.project_class is None:
                        logger.error(
                            f"Project class is not set for project {managed_project.project}"
                        )
                        managed_project.delete()

                        raise openportal.OpenPortalError(
                            f"Project class is not set for project {managed_project.project}"
                        )

                    generator = managed_project.project_class.get_generator()

                    if not generator:
                        logger.error(
                            f"Project class {managed_project.project_class} does not have a generator."
                        )
                        raise openportal.OpenPortalError(
                            f"Project class '{managed_project.project_class}' does not have a generator"
                        )

                    project_info.generate_shortname(generator)

                    if project_info.shortname is None:
                        logger.error(
                            f"Failed to generate shortname for project {managed_project.project}"
                        )
                        raise openportal.OpenPortalError(
                            f"Failed to generate shortname for project '{managed_project.project}'"
                        )

                local_identifier = self._to_project_identifier(project_info.shortname)

                managed_project.local_identifier = str(local_identifier)
                managed_project.save()

            return managed_project.get_mapping()

        # The project does not exist, so we need to create it

        # get the project class of the new project
        if details.project_class is None:
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"Project class is not set for project {details}"
            )

        if not isinstance(details.project_class, openportal.ProjectClass):
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"Invalid project class: {details.project_class}"
            )

        project_class = str(details.project_class).strip()

        if len(project_class) == 0:
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"Project class is empty for project {project}"
            )

        # See if we have an existing ProjectClass for the requesting remote portal and class
        remote_portal = str(identifier.portal)

        try:
            project_class = models.ProjectClass.objects.filter(
                portal=remote_portal, name=project_class
            ).first()
        except Exception:
            managed_project.delete()

            logger.warning(
                f"Failed to get the project class for portal {remote_portal} and class {project_class}. "
                "This suggests that the portal is not allowed to create projects in this class."
            )
            raise openportal.OpenPortalError(
                f"Project class '{project_class}' is not allowed for portal '{remote_portal}'"
            )

        if not project_class:
            managed_project.delete()

            logger.warning(
                f"Project class '{details.project_class}' not found for portal '{remote_portal}'. "
                "This suggests that the portal is not allowed to create projects in this class."
            )
            raise openportal.OpenPortalError(
                f"Project class '{details.project_class}' is not allowed for portal '{remote_portal}'"
            )

        # The remote portal is allowed to create projects in this class,
        # so we can now safely save the ManagedProject and create the project
        managed_project.project_class = project_class
        managed_project.details = str(details)
        managed_project.save()

        # get the customer (organisation) in which the project should be created
        if project_class.customer is None:
            raise openportal.OpenPortalError(
                f"Customer is not set for project {details}"
            )

        customer = project_class.customer

        # now get a generator for the project shortname
        generator = project_class.get_generator()

        if not generator:
            raise openportal.OpenPortalError(
                f"Project class '{project_class}' does not have a generator"
            )

        # at a minimum, we need to know the name of the project
        if details.name is None:
            raise openportal.OpenPortalError(
                f"Project name is not set for project {details}"
            )

        project_name = str(details.name).strip()

        if len(project_name) == 0:
            raise openportal.OpenPortalError(
                f"Project name is empty for project {identifier}"
            )

        # create the project in the customer
        waldur_project = structure_models.Project.objects.create(
            name=project_name,
            customer=customer,
        )

        managed_project.project = waldur_project
        managed_project.save()

        # Now create a unique shortname for this project using
        # the generator from the project class
        project_info = models.ProjectInfo.objects.create(
            project=waldur_project,
        )

        shortname = project_info.generate_shortname(generator)

        managed_project.local_identifier = str(self._to_project_identifier(shortname))
        managed_project.save()

        # now force an update of the project details
        self.update_project(
            identifier=identifier,
            new_details=details,
            force_update=True,
        )

        return managed_project.get_mapping()

    def update_project(
        self,
        identifier: openportal.ProjectIdentifier,
        new_details: openportal.ProjectDetails,
        force_update: bool = False,
    ) -> openportal.ProjectMapping:
        """
        Update a project in OpenPortal with the given identifier and details.
        This returns the mapping from the identifier in the requesting portal
        to the OpenPortal project identifier used internally.
        """
        logger.info(f"Updating project {identifier} with details {new_details}")

        if not isinstance(identifier, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(
                f"Invalid project identifier: {identifier}"
            )

        if not isinstance(new_details, openportal.ProjectDetails):
            raise openportal.OpenPortalError(f"Invalid project details: {new_details}")

        # Get the ManagedProject for this identifier, which must already exist
        try:
            managed_project = models.ManagedProject.objects.get(
                identifier=str(identifier)
            )
        except models.ManagedProject.DoesNotExist:
            logger.error(
                f"ManagedProject for identifier {identifier} does not exist. Cannot update project."
            )
            raise openportal.OpenPortalError(
                f"ManagedProject for identifier '{identifier}' does not exist"
            )

        if managed_project.project is None:
            logger.error(
                f"ManagedProject {managed_project} does not have an associated project. Cannot update project."
            )
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' does not have an associated project"
            )

        if managed_project.project.is_expired or managed_project.project.is_removed:
            # we can't make any changes to this project - return an error
            logger.error(
                f"ManagedProject {managed_project} is expired or removed, cannot update project."
            )
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' is expired or removed, cannot update project"
            )

        # first, make sure that the current project details are properly
        # set in the project...
        self._verify_existing_project_details(managed_project)

        # check to see any of the details have changed - if not, skip the update
        if not force_update and managed_project.details == str(new_details):
            logger.info(
                f"Project {identifier} details have not changed, skipping update."
            )
            return managed_project.get_mapping()

        # get the project being managed
        project = managed_project.project
        details = managed_project.get_details()

        if new_details.name is not None:
            if details.name != new_details.name:
                project.name = str(new_details.name).strip()
                details.name = str(new_details.name).strip()

        if new_details.description is not None:
            if details.description != new_details.description:
                project.description = str(new_details.description).strip()
                details.description = str(new_details.description).strip()

        if new_details.start_date is not None:
            if details.start_date != new_details.start_date:
                project.start_date = new_details.start_date
                details.start_date = new_details.start_date

        if new_details.end_date is not None:
            if details.end_date != new_details.end_date:
                project.end_date = new_details.end_date
                details.end_date = new_details.end_date

        if new_details.members is not None:
            # Update the members of the project
            for member, role in new_details.members.items():
                old_role = details.members.get(member, None)

                if old_role is None or old_role != role:
                    logger.info(
                        f"Adding member {member} with role {role} to project {identifier}"
                    )
                    details.members[member] = role

                # note that we don't remove people from a project!

        if new_details.credit is not None:
            if details.credit != new_details.credit:
                logger.info(
                    f"Setting credit {new_details.credit} for project {identifier}"
                )
                details.credit = new_details.credit

        # save the updated project and details
        project.save()
        managed_project.set_details(details)
        managed_project.save()

        return managed_project.get_mapping()

    def get_project(
        self, identifier: openportal.ProjectIdentifier
    ) -> openportal.ProjectDetails:
        """
        Get a project from OpenPortal with the given identifier.
        This returns the details of the project, e.g. its name,
        description, members etc.
        """
        if not isinstance(identifier, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(
                f"Invalid project identifier: {identifier}"
            )

        # Get the ManagedProject for this identifier, which must already exist
        try:
            managed_project = models.ManagedProject.objects.get(
                identifier=str(identifier)
            )
        except models.ManagedProject.DoesNotExist:
            logger.error(f"ManagedProject for identifier {identifier} does not exist.")
            raise openportal.OpenPortalError(
                f"ManagedProject for identifier '{identifier}' does not exist"
            )

        if managed_project.project is None:
            logger.error(
                f"ManagedProject {managed_project} does not have an associated project."
            )
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' does not have an associated project"
            )

        project = managed_project.project

        if project.is_expired or project.is_removed:
            # we can't make any changes to this project - return an error
            logger.error(f"ManagedProject {managed_project} is expired or removed.")
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' is expired or removed"
            )

        details = openportal.ProjectDetails("{}")

        if project.name is not None:
            details.name = str(project.name).strip()

        if project.description is not None:
            details.description = str(project.description).strip()

        if managed_project.project_class is not None:
            details.project_class = openportal.ProjectClass(
                managed_project.project_class.name,
            )

        # Eventually add in the users in their roles etc.

        return details

    def get_project_mapping(
        self, identifier: openportal.ProjectIdentifier
    ) -> openportal.ProjectMapping:
        """
        Get the mapping for a project in OpenPortal with the given identifier.
        This returns the mapping from the identifier in the requesting portal
        to the OpenPortal project identifier used internally.
        """
        if not isinstance(identifier, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(
                f"Invalid project identifier: {identifier}"
            )

        # Get the ManagedProject for this identifier, which must already exist
        try:
            managed_project = models.ManagedProject.objects.get(
                identifier=str(identifier)
            )
        except models.ManagedProject.DoesNotExist:
            logger.error(f"ManagedProject for identifier {identifier} does not exist.")
            raise openportal.OpenPortalError(
                f"ManagedProject for identifier '{identifier}' does not exist"
            )

        if managed_project.project is None:
            logger.error(
                f"ManagedProject {managed_project} does not have an associated project."
            )
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' does not have an associated project"
            )

        project = managed_project.project

        if project.is_expired or project.is_removed:
            # we can't make any changes to this project - return an error
            logger.error(f"ManagedProject {managed_project} is expired or removed.")
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' is expired or removed"
            )

        return managed_project.get_mapping()

    def get_usage_report(
        self,
        identifier: openportal.ProjectIdentifier,
        date_range: openportal.DateRange,
    ) -> openportal.UsageReport:
        """
        Get a usage report for a project in OpenPortal for the given date range.
        This returns the usage report, which contains the usage data for the project.
        """
        if not isinstance(identifier, openportal.ProjectIdentifier):
            raise openportal.OpenPortalError(
                f"Invalid project identifier: {identifier}"
            )

        if not isinstance(date_range, openportal.DateRange):
            raise openportal.OpenPortalError(f"Invalid date range: {date_range}")

        # Get the ManagedProject for this identifier, which must already exist
        try:
            managed_project = models.ManagedProject.objects.get(
                identifier=str(identifier)
            )
        except models.ManagedProject.DoesNotExist:
            logger.error(f"ManagedProject for identifier {identifier} does not exist.")
            raise openportal.OpenPortalError(
                f"ManagedProject for identifier '{identifier}' does not exist"
            )

        if managed_project.project is None:
            logger.error(
                f"ManagedProject {managed_project} does not have an associated project."
            )
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' does not have an associated project"
            )

        project = managed_project.project

        if project.is_removed:
            # we can't make any changes to this project - return an error
            logger.error(f"ManagedProject {managed_project} is removed.")
            raise openportal.OpenPortalError(
                f"ManagedProject '{managed_project}' is removed"
            )

        return openportal.UsageReport(openportal.PortalIdentifier("brics"))

    def send_result(self, job: openportal.Job) -> None:
        """
        Send the result of a job back to OpenPortal.
        """
        logger.info(f"Sending result for job {job}")

        if not isinstance(job, openportal.Job):
            raise openportal.OpenPortalError(f"Invalid job: {job}")

        openportal.send_result(job)
