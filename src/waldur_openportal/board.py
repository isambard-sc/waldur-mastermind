import logging
import os
import json

from waldur_core.structure import models as structure_models
from waldur_core.core.enums import ReviewStates
from waldur_core.core.utils import get_system_robot

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

        if details.allocation is not None:
            logger.warning("Need to verify project allocation!")

    def _get_project_template(
        self, managed_project: models.ManagedProject, details: openportal.ProjectDetails
    ) -> models.ProjectTemplate:
        """
        Get the project class for the managed project.

        Note that this will delete the ManagedProject if the project class
        is invalid and cannot be determined. This is because an invalid
        project class means that this project cannot be created
        """
        if managed_project.has_project_template():
            managed_project.set_details(details)
            managed_project.save()
            return managed_project.get_project_template()

        if not managed_project.has_remote_identifier():
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"ManagedProject {managed_project} does not have an identifier set"
            )

        identifier = managed_project.get_remote_identifier()

        # get the project class of the new project
        if details.project_template is None:
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"Project class is not set for project {details}"
            )

        if not isinstance(details.project_template, openportal.ProjectTemplate):
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"Invalid project class: {details.project_template}"
            )

        project_template = str(details.project_template).strip()

        if len(project_template) == 0:
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"Project class is empty for project {project}"
            )

        # See if we have an existing ProjectTemplate for the requesting remote portal and class
        remote_portal = str(identifier.portal)

        try:
            project_template = models.ProjectTemplate.objects.filter(
                portal=remote_portal, name=project_template
            ).first()
        except Exception:
            managed_project.delete()

            logger.warning(
                f"Failed to get the project class for portal {remote_portal} and class {project_template}. "
                "This suggests that the portal is not allowed to create projects in this class."
            )
            raise openportal.OpenPortalError(
                f"Project class '{project_template}' is not allowed for portal '{remote_portal}'"
            )

        if not project_template:
            managed_project.delete()

            logger.warning(
                f"Project class '{details.project_template}' not found for portal '{remote_portal}'. "
                "This suggests that the portal is not allowed to create projects in this class."
            )
            raise openportal.OpenPortalError(
                f"Project class '{details.project_template}' is not allowed for portal '{remote_portal}'"
            )

        # The remote portal is allowed to create projects in this class,
        # so we can now safely save the ManagedProject and create the project
        managed_project.set_project_template(project_template)
        managed_project.set_details(details)
        managed_project.save()

        return project_template

    def _attach_existing_project(
        self,
        managed_project: models.ManagedProject,
        existing_project: structure_models.Project,
    ) -> openportal.ProjectMapping:
        if managed_project.project is None:
            managed_project.project = existing_project
            managed_project.save()
        elif managed_project.project != existing_project:
            # This is a bug - we should not have a ManagedProject with a different project
            logger.error(
                f"ManagedProject {managed_project} already has a project {managed_project.project}, but we are trying to attach {existing_project}"
            )
            raise openportal.OpenPortalError(
                f"ManagedProject {managed_project} already has a project {managed_project.project}, but we are trying to attach {existing_project}"
            )

        identifier = managed_project.get_remote_identifier()

        if identifier is None:
            # This is a bug - we should not have a ManagedProject without an identifier
            logger.error(f"{managed_project} does not have an identifier set.")
            managed_project.reject(
                get_system_robot(),
                f"{managed_project} does not have an identifier set.",
            )
            raise openportal.OpenPortalError("Project is rejected!")

        if managed_project.project.is_expired or managed_project.project.is_removed:
            # any changes to this project are now not allowed - this is rejected
            logger.warning(
                f"{identifier} is expired or removed, cannot create project."
            )
            managed_project.reject(
                get_system_robot(),
                f"{identifier} is expired or removed, cannot create project.",
            )
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        # we have already created this project, so we can just return the mapping - check
        # there the project details are in agreement with the existing project
        if managed_project.details is None:
            # This is a bug
            logger.warning(
                f"Details for {identifier} are None, but the project already exists."
            )
            managed_project.reject(
                get_system_robot(),
                f"{identifier} details are None, but the project already exists.",
            )
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        if managed_project.local_identifier is None:
            self._get_local_identifier(managed_project)

        return managed_project.get_mapping()

    def _get_local_identifier(self, managed_project: models.ManagedProject):
        # Now create a unique shortname for this project using
        # the generator from the project class
        if managed_project is None:
            raise openportal.OpenPortalError(
                f"ManagedProject {managed_project} is None - cannot generate local identifier"
            )

        waldur_project = managed_project.project
        project_template = managed_project.get_project_template()

        if waldur_project is None:
            logger.error(
                f"ManagedProject {managed_project} does not have a project set."
            )
            managed_project.reject(
                get_system_robot(),
                f"ManagedProject {managed_project} does not have a project set.",
            )
            raise openportal.OpenPortalError(f"{managed_project} is rejected!")

        project_info, created = models.ProjectInfo.objects.get_or_create(
            project=waldur_project,
        )

        if project_info.has_shortname():
            shortname = project_info.get_shortname()
        else:
            project_template = managed_project.get_project_template()

            if project_template is None:
                logger.error(
                    f"Project class is not set for project {managed_project.project}"
                )
                managed_project.reject(
                    get_system_robot(),
                    f"Project class is not set for project {managed_project.project}",
                )
                raise openportal.OpenPortalError(f"{managed_project} is rejected!")

            generator = project_template.get_generator()

            if generator is None:
                logger.error(
                    f"Project class {project_template} does not have a generator set."
                )
                managed_project.reject(
                    get_system_robot(),
                    f"Project class {project_template} does not have a generator set.",
                )
                raise openportal.OpenPortalError(f"{managed_project} is rejected!")

            shortname = project_info.generate_shortname(generator)

        managed_project.local_identifier = str(self._to_project_identifier(shortname))
        managed_project.save()

    def _create_local_project(self, managed_project: models.ManagedProject):
        if managed_project.project is not None:
            # This project already exists - nothing to do?
            return

        identifier = managed_project.get_remote_identifier()
        project_template: models.ProjectTemplate = managed_project.project_template
        details: openportal.ProjectDetails = managed_project.get_details()

        if identifier is None or project_template is None or details is None:
            # This is a bug - we should not have a ManagedProject without a project class
            logger.error(f"{managed_project} is in an invalid state.")
            managed_project.reject(
                get_system_robot(),
                f"{managed_project} is in an invalid state - project class or customer is not set.",
            )
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        # get the customer (organisation) in which the project should be created
        if project_template.customer is None:
            managed_project.reject(
                get_system_robot(),
                f"Project class {project_template} does not have a customer set.",
            )
            logger.warning(
                f"Project class {project_template} does not have a customer set."
            )
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        customer = project_template.customer

        # there is a change that this project has already been created.
        # Look for an existing project in this customer that has the
        # same name as the project we are trying to create
        existing_projects = structure_models.Project.objects.filter(
            customer=customer,
            name=str(details.name).strip(),
        )

        orphaned_existing_project = None

        for existing_project in existing_projects:
            # check if this project already has a ManagedProject
            try:
                existing_managed_project = models.ManagedProject.objects.get(
                    project=existing_project,
                )
                logger.info(
                    f"Found existing ManagedProject {existing_managed_project} for project {existing_project}"
                )
            except models.ManagedProject.DoesNotExist:
                logger.info(
                    f"Found existing project {existing_project} without a ManagedProject"
                )

                if not (existing_project.is_expired or existing_project.is_removed):
                    # this project is not expired or removed, so we can use it
                    # as an orphaned project
                    logger.info(
                        f"Using existing project {existing_project} as orphaned project for identifier {identifier}"
                    )
                    orphaned_existing_project = existing_project
                    break

        if orphaned_existing_project:
            # We have found an existing project that does not have a ManagedProject
            # associated with it. This means that the project was created in the
            # customer, but not managed by OpenPortal.
            logger.info(
                f"Using orphaned existing project {orphaned_existing_project} for identifier {identifier}"
            )

            # We can now attach this project to the ManagedProject
            self._attach_existing_project(managed_project, orphaned_existing_project)

            if managed_project.is_rejected():
                raise openportal.OpenPortalError(f"{identifier} is rejected!")
            else:
                # We need to ask the site admin to approve this connection
                managed_project.set_needs_approval(
                    True,
                    comment=f"Project {orphaned_existing_project} already exists in customer {customer} and is being attached to ManagedProject {managed_project}.",
                )
                raise openportal.OpenPortalError(f"{identifier} needs approval!")

        # now get a generator for the project shortname
        generator = project_template.get_generator()

        if not generator:
            managed_project.reject(
                get_system_robot(),
                f"Project class {project_template} does not have a generator.",
            )
            logger.warning(
                f"Project class {project_template} does not have a generator."
            )
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        # at a minimum, we need to know the name of the project
        if details.name is None:
            managed_project.reject(
                get_system_robot(),
                f"Project name is not set for project {details}",
            )
            logger.warning(f"Project name is not set for project {details}")
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        project_name = str(details.name).strip()

        if len(project_name) == 0:
            managed_project.reject(
                get_system_robot(),
                f"Project name is empty for project {identifier}",
            )
            logger.warning(f"Project name is empty for project {identifier}")
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        # create the project in the customer
        waldur_project = structure_models.Project.objects.create(
            name=project_name,
            customer=customer,
        )

        managed_project.project = waldur_project
        managed_project.save()

        self._get_local_identifier(managed_project)

    def create_project(
        self,
        identifier: openportal.ProjectIdentifier,
        details: openportal.ProjectDetails,
        force_request_approval: bool = False,
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
        managed_project, created = models.ManagedProject.objects.get_or_create(
            identifier=str(identifier),
            defaults={
                "details": json.loads(str(details)),
                "local_identifier": None,
                "project_template": None,
                "project": None,
                "state": ReviewStates.DRAFT,
                "reviewed_by": None,
                "reviewed_at": None,
                "review_comment": None,
            },
        )

        if created:
            logger.info(
                f"Created new ManagedProject for identifier {identifier}: {managed_project}"
            )
        else:
            logger.info(
                f"Retrieved existing ManagedProject for identifier {identifier}: {managed_project}"
            )

        # get the project class of this project
        project_template = self._get_project_template(managed_project, details)

        if force_request_approval:
            if not managed_project.is_rejected():
                # If the project is not rejected, we need to set it to needs approval
                logger.info(
                    f"Project {identifier} requires approval for creation due to force_request_approval"
                )
                managed_project.set_needs_approval()

        # We can't do anything if the project is pending approval or canceled
        if managed_project.is_pending():
            logger.warning(f"{identifier} is pending approval!")
            raise openportal.OpenPortalError(f"{identifier} is pending approval!")
        elif managed_project.is_canceled():
            logger.warning(f"{identifier} is canceled!")
            raise openportal.OpenPortalError(f"{identifier} is canceled!")
        elif managed_project.is_rejected():
            logger.warning(f"{identifier} is rejected!")
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        if project_template is None:
            # This is a bug - we should not have a ManagedProject without a project class
            logger.error(f"{identifier} does not have a project class set")
            managed_project.delete()

            raise openportal.OpenPortalError(
                f"{identifier} does not have a project class set"
            )

        if (
            project_template.action_needs_approval()
            and not managed_project.is_approved()
        ):
            # We need to approve creation requests for this project class
            logger.info(
                f"Project {identifier} with class {managed_project.project_template} requires approval for project creation"
            )
            managed_project.set_needs_approval()

            # Here you would typically send a notification to the admin or
            # the person responsible for approving project creation requests.
            # For now, we will just raise an error to indicate that approval is needed.
            raise openportal.OpenPortalError(
                f"{identifier} requires approval for project creation"
            )
        elif not managed_project.is_approved():
            # If the project class does not require approval, we can proceed
            logger.info(
                f"Project {identifier} with class {managed_project.project_template} does not require approval for project creation."
            )
            managed_project.set_needs_approval(False)

        if managed_project.project is not None:
            return self._attach_existing_project(
                managed_project, managed_project.project
            )

        self._create_local_project(managed_project)

        # now force an update of the project details
        return self.update_project(
            identifier=identifier,
            new_details=details,
            force_update=True,
        )

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
            logger.warning(
                f"ManagedProject for identifier {identifier} does not exist - recreating."
            )

            # recreate the project, but make sure to ask for approval
            # so that the site admin can reject this request
            return self.create_project(
                identifier=identifier, details=new_details, force_request_approval=True
            )

        # We can't do anything if the project is pending approval or canceled
        if managed_project.is_pending():
            logger.warning(f"{identifier} is pending approval!")
            raise openportal.OpenPortalError(f"{identifier} is pending approval!")
        elif managed_project.is_canceled():
            logger.warning(f"{identifier} is canceled!")
            raise openportal.OpenPortalError(f"{identifier} is canceled!")
        elif managed_project.is_rejected():
            logger.warning(f"{identifier} is rejected!")
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        if managed_project.project_template is None:
            # This is a bug - we should not have a ManagedProject without a project class
            logger.error(
                f"{identifier} does not have a project class set. Cannot update project."
            )
            managed_project.delete()
            raise openportal.OpenPortalError(
                f"{identifier} does not have a project class set"
            )

        if (
            managed_project.project_template.action_needs_approval()
            and not managed_project.is_approved()
        ):
            # We need to approve update requests for this project class
            logger.info(
                f"{identifier} with class {managed_project.project_template} requires approval for project updates."
            )

            managed_project.set_needs_approval()

            # Here you would typically send a notification to the admin or
            # the person responsible for approving project update requests.
            # For now, we will just raise an error to indicate that approval is needed.
            raise openportal.OpenPortalError(
                f"{identifier} with class {managed_project.project_template} requires approval for project updates"
            )

        if managed_project.project is None:
            # we actually need to create the project
            logger.warning(
                f"ManagedProject {managed_project} does not have an associated project, creating a new one."
            )
            self._create_local_project(managed_project)

        if managed_project.project.is_expired or managed_project.project.is_removed:
            # we can't make any changes to this project - return an error
            managed_project.reject(
                get_system_robot(),
                f"{identifier} is expired or removed, cannot update project.",
            )
            logger.warning(
                f"{identifier} is expired or removed, cannot update project."
            )
            raise openportal.OpenPortalError(f"{identifier} is rejected!")

        if managed_project.local_identifier is None:
            logger.warning(
                f"ManagedProject {managed_project} does not have a local identifier, copying from the Project."
            )
            self._get_local_identifier(managed_project)

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

        if new_details.allocation is not None:
            if details.allocation != new_details.allocation:
                # check that we approve this allocation change
                if managed_project.project_template.action_needs_approval(
                    allocation=new_details.allocation
                ):
                    logger.info(
                        f"{identifier} with class {managed_project.project_template} requires approval for allocation changes."
                    )
                    managed_project.set_needs_approval()
                    raise openportal.OpenPortalError(f"{identifier} needs approval!")

                logger.info(
                    f"Setting allocation {new_details.allocation} for project {identifier}"
                )
                details.allocation = new_details.allocation

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

        if managed_project.project_template is not None:
            details.project_template = openportal.ProjectTemplate(
                managed_project.project_template.name,
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
