
import logging
import operator
import re
from functools import reduce

from django.conf import settings as django_settings
from django.db import transaction
from django.utils import timezone

from waldur_core.structure.backend import ServiceBackend
from waldur_core.structure.exceptions import ServiceBackendError
from waldur_openportal import signals
from waldur_openportal.client import OpenPortalClient
from waldur_openportal.structures import Quotas

from . import base, models
from .utils import sanitize_allocation_name
from . import op as openportal

logger = logging.getLogger(__name__)


class OpenPortalBackend(ServiceBackend):
    def __init__(self, settings):
        self.settings = settings
        self.client = self.get_client(settings)

    def destination(self) -> openportal.Destination:
        """
        Return the OpenPortal Destination for the instance
        being managed by this backend
        """
        return self.client.destination()

    def get_client(self, settings):
        logger.info(f"Creating OpenPortal client for settings: {settings}")
        return OpenPortalClient(
            instance_name=settings.options.get("instance_name", None),
        )

    def pull_resources(self):
        logger.info(f"Pulling OpenPortal resources for settings: {self}")
        for allocation in self.get_allocation_queryset().filter(
            state=models.Allocation.States.OK
        ):
            try:
                logger.info("About to pull allocation %s", allocation)
                self.pull_allocation(allocation)
            except Exception as e:
                logger.error("Error while pulling allocation [%s]: %s", allocation, e)

    def ping(self, raise_exception=False):
        logger.info(f"Pinging OpenPortal")
        try:
            self.client.health()
        except base.BatchError as e:
            logger.error(f"OpenPortal is not available: {e}")
            if raise_exception:
                raise ServiceBackendError(e)
            return False
        else:
            return True

    def get_project_shortname(self, project):
        """
        Return the preferred shortname for the passed project.
        """
        # look up the short name from the models.ProjectInfo object
        # associated with this project
        project_info, created = models.ProjectInfo.objects.get_or_create(project=project)

        project = project_info.project

        # if this is not set, then copy it in from the project.short_name
        # property (which may disappear in the future)
        if project_info.shortname is None and hasattr(project, "short_name"):
            if project.short_name is not None:
                logger.info(f"Copying shortname from the project's short_name for {project}")
                project_info.set_shortname(project.shortname)
                project_info.save()

        if project_info.shortname is None:
            logger.error(f"Empty shortname for project: {project}")

        return project_info.shortname

    def get_user_shortname(self, user):
        """
        Return the preferred shortname for the passed user.
        """
        # look up the short name from the models.UserInfo object
        # associated with this user
        user_info, created = models.UserInfo.objects.get_or_create(user=user)

        user = user_info.user

        # if this is not set, then copy it in from the user.unix_username
        # property (which may disappear in the future)
        if user_info.shortname is None and hasattr(user, "unix_username"):
            if user.unix_username is not None:
                logger.info(f"Copying shortname from the user's unix_username for {user}")
                user_info.set_shortname(user.unix_username)
                user_info.save()

        if user_info.shortname is None:
            logger.error(f"Empty shortname for user: {user}")

        return user_info.shortname

    def sync_users(self, allocation: models.Allocation) -> None:
        if not isinstance(allocation, models.Allocation):
            raise ServiceBackendError(
                "Invalid allocation type %s" % type(allocation)
            )

        if not allocation.has_project_identifier():
            logger.warning(f"Allocation {allocation} has no project identifier - creating now!")
            # this already calls 'sync_users' on the created allocation
            self.create_allocation(allocation)
            return

        project = allocation.get_project_identifier()
        logger.info(f"Syncing users for allocation: {allocation} | {project}")
        users = allocation.project.get_users()
        logger.info(f"Users for allocation: {users}")

        # list all users who OpenPortal thinks are in the project
        user_mappings = self.client.get_users(project)

        logger.info(f"Users of {project} in OpenPortal: {user_mappings}")

        allocated_mappings = []

        # go through and add the users who are not in OpenPortal
        for user in users:
            try:
                # get the association between the user and the allocation
                (association, created) = models.Association.objects.get_or_create(user=user, allocation=allocation)

                mapping = None

                if association.has_mapping():
                    mapping = association.get_mapping()

                if mapping is None or mapping not in user_mappings:
                    logger.info(f"Adding user {user} to OpenPortal")
                    shortname = self.get_user_shortname(user)

                    if shortname is None or not shortname.strip():
                        logger.error(f"Empty shortname for user: {user} - cannot add to OpenPortal")
                        continue

                    new_mapping = self.client.add_user(shortname=shortname, project=project)

                    logger.info(f"Added user {user} to OpenPortal project {project} with mapping {new_mapping}")

                    if (mapping is not None) and (new_mapping != mapping):
                        logger.warning(f"User {user} has a changing username in OpenPortal: {mapping} -> {new_mapping}")

                    mapping = new_mapping

                    association.set_mapping(mapping)
                    association.save()

                    signals.openportal_association_created.send(
                        models.Allocation,
                        allocation=allocation,
                        user=user,
                    )

                allocated_mappings.append(mapping)
            except Exception as e:
                logger.error(f"Unable to add user {user} to OpenPortal: {e}")

        stale_mappings = [mapping for mapping in user_mappings if mapping not in allocated_mappings]

        if len(stale_mappings) > 0:
            logger.info(f"Stale users in OpenPortal: {stale_mappings}")

        for mapping in stale_mappings:
            try:
                self.client.delete_user(mapping.user)
                # no need to signal as the user has already been removed from the association
            except Exception as e:
                logger.error(f"Unable to delete user with mapping {mapping} from OpenPortal: {e}")

    def assert_can_create_allocation_for_project(self, project):
        """
        This checks to see if the passed project is allowed to create an allocation
        on the instance managed by this backend. Projects are only allowed to create
        a single allocation per instance, and they must have a routing path
        that matches the destination of this instance.
        """
        destination = str(self.client.destination())

        logger.info(f"Asserting that project {project} can create an allocation for {destination}")

        existing_allocations = self.get_allocation_queryset().filter(project=project)

        for allocation in existing_allocations:
            logger.info(f"Existing allocation: {allocation} | {allocation.state} | {allocation.is_active} | {allocation.has_project_identifier()}")

        # find all of these allocations that are active and that have a project identifier
        existing_allocations = [
            allocation for allocation in existing_allocations
            if allocation.has_project_identifier() and allocation.state != models.Allocation.States.ERRED
        ]

        if len(existing_allocations) > 0:
            logger.error(f"Project {project} already has existing allocation(s) in OpenPortal for {destination}")
            logger.error(f"These are {existing_allocations}")
            raise ServiceBackendError(
                f"Project {project} already has an allocation for {destination} in OpenPortal. " +
                 "You may only have a single active allocation per destination per project. " +
                 f"The existing allocation(s) are: {existing_allocations}")

        # now look at the allowed destinations for this project, from its
        # project-info object
        project_info, created = models.ProjectInfo.objects.get_or_create(project=project)
        project_info.sanitise()

        if project_info.allowed_destinations is None:
            logger.error(f"Project {project} has no allowed destinations")
            raise ServiceBackendError(
                f"Project {project} has no allowed OpenPortal destinations, so cannot create an allocation on {destination}")

        allowed_destinations = project_info.allowed_destinations.split(",")

        for allowed_destination in allowed_destinations:
            allowed_destination = allowed_destination.strip()

            # the allowed_destination is a regular expression, so we need to match it
            if allowed_destination == destination:
                # we have an exact match
                return
            elif allowed_destination == "*":
                # this is a wildcard, so we allow it
                return
            else:
                if re.match(allowed_destination, destination):
                    # this is a match
                    return

        logger.error(f"Project {project} is not allowed to create an allocation for {destination}")
        logger.error(f"Allowed destinations are: {allowed_destinations}")

        raise ServiceBackendError(
            f"Project {project} is not allowed to create an allocation for {destination}. " +
            f"Allowed destinations are: {allowed_destinations}")

    def create_allocation(self, allocation):
        if allocation.has_project_identifier():
            project = allocation.get_project_identifier()
            logger.info(f"Allocation already exists: {allocation} | {project}")

            # add it again just to be sure
            mapping = self.client.add_project(project)

            logger.info(f"Re-added allocation {allocation} to OpenPortal with mapping {mapping}")

            if allocation.has_mapping():
                if allocation.get_mapping() != mapping:
                    logger.warning(f"Allocation {allocation} has a changing project name in OpenPortal: {mapping} -> {allocation.get_mapping()}")
                else:
                    allocation.set_mapping(mapping)
        else:
            self.assert_can_create_allocation_for_project(allocation.project)

            project = allocation.project
            project_name = self.get_project_shortname(project)

            logger.info(f"Creating allocation: {allocation} for project {project_name}")

            if project_name is None or not project_name.strip():
                logger.error(f"Empty project_name for allocation: {allocation} - cannot create in OpenPortal")
                raise ServiceBackendError(f"Empty project_name for allocation. Please set a short name for {project}")

            mapping = self.client.add_project(project_name)

            logger.info(f"Created OpenPortal project {project_name} with mapping {mapping}")

            allocation.set_mapping(mapping)

        allocation.node_limit = 0
        allocation.save()

        self.set_resource_limits(allocation)

        if allocation.has_project_identifier():
            self.sync_users(allocation)
        else:
            logger.error(f"Program bug? Allocation {allocation} has no project identifier - cannot sync users")
            raise ServiceBackendError(f"Allocation {allocation} for {project} has no project identifier - cannot sync users")

    def delete_allocation(self, allocation):
        logger.info(f"Deleting allocation: {allocation}")

        if not allocation.has_project_identifier():
            logger.info(f"Allocation already deleted: {allocation}")
        else:
            try:
                project = allocation.get_project_identifier()
                self.client.delete_project(project)
            except Exception as e:
                logger.error(f"Unable to delete allocation {allocation} from OpenPortal: {e}")

        project = allocation.project
        if self.get_allocation_queryset().filter(project=project).count() == 0:
            self.delete_project(project)

    def add_user(self, allocation: models.Allocation, user) -> bool:
        """
        Create association between user and OpenPortal account if it does not exist yet.
        The allocation contains the information of which project the user is in.
        """
        if not isinstance(allocation, models.Allocation):
            raise ServiceBackendError(
                "Invalid allocation type %s" % type(allocation)
            )

        if not allocation.has_project_identifier():
            logger.error(f"Allocation {allocation} has no project identifier - cannot add user {user} to OpenPortal")
            return False

        project = allocation.get_project_identifier()

        logger.info(f"Adding user {user} to project {project} in OpenPortal")

        shortname = self.get_user_shortname(user)

        if shortname is None or not shortname.strip():
            logger.error(f"Empty shortname for user: {user} - they cannot be added to OpenPortal")
            return False

        # get or create the association between the user and the allocation
        # This association holds the username of the user in OpenPortal on this instance
        (association, created) = models.Association.objects.get_or_create(user=user, allocation=allocation)

        mapping = None

        if association.has_mapping():
            mapping = association.get_mapping()

        if mapping is not None:
            logger.info(f"User {user} has previously been in {project} with mapping {mapping}")
            logger.info("Re-adding them to OpenPortal with the same mapping.")

        try:
            new_mapping = self.client.add_user(shortname=shortname, project=project)
            logger.info(f"Added user {user} with mapping {new_mapping}")

            if (mapping is not None) and (new_mapping != mapping):
                logger.warning(f"User {user} has a changing mapping in OpenPortal: {mapping} -> {new_mapping}")

            association.set_mapping(new_mapping)
            association.save()

            signals.openportal_association_created.send(
                models.Allocation,
                allocation=allocation,
                user=user,
            )
        except Exception as e:
            logger.error(f"Unable to add user {user} to allocation {allocation} in OpenPortal: {e}")
            return False

        return True

    def delete_user(self, allocation: models.Allocation, user) -> bool:
        """
        Delete association between user and OpenPortal account if it exists.
        """
        if not isinstance(allocation, models.Allocation):
            raise ServiceBackendError(
                "Invalid allocation type %s" % type(allocation)
            )

        if not allocation.has_project_identifier():
            logger.error(f"Allocation {allocation} has no project identifier - cannot delete user {user} from OpenPortal")
            return False

        project = allocation.get_project_identifier()

        logger.info(f"Deleting OpenPortal user {user} from project {project}")

        # find the association between the user and the allocation
        try:
            association = models.Association.objects.get(user=user, allocation=allocation)
        except Exception as e:
            logger.error(f"Unable to find association between user {user} and allocation {allocation}: {e}")
            return False

        if not association.has_mapping():
            logger.warning(f"User {user} is not associated with OpenPortal?")
            return False

        op_user = association.get_user_identifier()

        try:
            logger.info(f"Deleting user {op_user} from project {project} in OpenPortal")

            try:
                self.client.delete_user(op_user)
            except Exception as e:
                logger.error(f"Unable to delete user {op_user} from project {project} in OpenPortal: {e}")

                # see if this user still exists in the project - if not, we can continue
                mappings = self.client.get_users(project)

                if association.get_mapping() in mappings:
                    logger.error(f"User {op_user} still exists in project {project} - cannot delete")
                    return False

            # delete this association
            association.delete()

            signals.openportal_association_deleted.send(
                models.Allocation, allocation=allocation, user=user
            )

            return True
        except Exception as e:
            logger.error(f"Unable to delete user {user} from allocation {allocation} in OpenPortal: {e}")
            return False

    def set_resource_limits(self, allocation: models.Allocation):
        if not isinstance(allocation, models.Allocation):
            raise ServiceBackendError(
                "Invalid allocation type %s" % type(allocation)
            )

        if not allocation.has_project_identifier():
            logger.error(f"Allocation {allocation} has no project identifier - cannot set resource limits")
            return

        project = allocation.get_project_identifier()

        logger.info(f"Setting resource limits for allocation {project}")
        limits = Quotas(
            node=allocation.node_limit,
        )
        self.client.set_resource_limits(project, limits)

    def sync_usage(self, allocation: models.Allocation):
        if not isinstance(allocation, models.Allocation):
            raise ServiceBackendError(
                "Invalid allocation type %s" % type(allocation)
            )

        if not allocation.has_project_identifier():
            logger.error(f"Allocation {allocation} has no project identifier - cannot sync usage")
            return

        project = allocation.get_project_identifier()
        logger.info(f"Syncing OpenPortal usage for allocation {allocation} and project {project}")

        # accounting is based on collecting monthly reports
        report = self.client.get_usage_report(project, openportal.DateRange.this_month())

        logger.info(f"Usage report for project {project}:\n{report}")

        self._update_usage_from_report(allocation, report)
        limits = self.get_allocation_limits(project)
        self._update_limits(allocation, limits)

    def pull_allocation(self, allocation: models.Allocation):
        if not isinstance(allocation, models.Allocation):
            raise ServiceBackendError(
                "Invalid allocation type %s" % type(allocation)
            )

        if not allocation.has_project_identifier():
            raise ServiceBackendError(
                "Allocation %s has no project identifier - cannot pull from OpenPortal" % allocation
            )

        logger.info(f"Pulling OpenPortal allocation {allocation}")
        self.sync_users(allocation)
        self.sync_usage(allocation)

    def get_allocation_limits(self, account):
        logger.info(f"Getting OpenPortal limits for account: {account}")
        limits = self.client.get_resource_limits(account)
        logger.info(f"OpenPortal limits for account {account}: {limits}")

    def _update_limits(self, allocation, limits):
        logger.info(f"Updating limits for OpenPortal allocation {allocation}")
        if not limits:
            return
        allocation.node_limit = limits.node
        allocation.save(update_fields=["node_limit"])

    @transaction.atomic()
    def _update_usage_from_report(self, allocation, report: openportal.ProjectUsageReport):
        # this will be the total usage this month - check that we have
        # dates that are all in the same month...
        if len(report.dates) == 0:
            logger.error(f"Empty usage report for {allocation}")
            return

        day = report.dates[0]

        for date in report.dates[1:]:
            if date.month != day.month or date.year != day.year:
                logger.error(f"Usage report for {allocation} spans multiple months")
                return

        allocation.node_usage = report.total_usage.node_seconds
        allocation.save(update_fields=["node_usage"])

        associations = models.Association.objects.filter(allocation=allocation)

        if len(associations) == 0:
            logger.warning(f"Allocation {allocation} has no associations - skipping")
            return

        for association in associations:
            user = association.user

            if not association.has_user_identifier():
                logger.warning(f"User {user} in {association} has no user identifier - skipping")
                continue

            user_identifier = association.get_user_identifier()

            # look up the usage for this user from the report
            try:
                usage = report.usage(user_identifier).node_seconds
            except Exception as e:
                logger.warning(f"User {user} has no usage in the report: {e}")
                usage = 0

            # we save usage using the UserIdentifier rather than the local
            # username, so that a consistent identifier is used across
            # all resources in a project
            models.AllocationUserUsage.objects.update_or_create(
                allocation=allocation,
                year=day.year,
                month=day.month,
                user=user,
                username=str(user_identifier),
                defaults={
                    "node_usage": usage
                },
            )

    def get_allocation_queryset(self):
        logger.info("Getting OpenPortal allocation queryset")
        return models.Allocation.objects.filter(service_settings=self.settings)

    def _update_allocation_associations(self, allocation):
        logger.info(f"Updating associations for allocation {allocation}")
        project = allocation.get_project_identifier()

        # get the UserMappings for all users that are registered with
        # OpenPortal for this allocation
        backend_users = self.client.get_users(project)

        # get the UserMappings for all users that Waldur says should
        # be associated with this allocation
        local_users = [
            association.get_mapping() for association in allocation.associations.all() if association.has_mapping()
        ]

        # Get the UserIdentifiers for all users that are in OpenPortal
        # who shouldn't be (because they are not in Waldur)
        stale_users = [user.user for user in backend_users if user not in local_users]

        # Now remove the associations for all of these users
        models.Association.objects.filter(
            allocation=allocation, useridentifier__in=stale_users
        ).delete()

        logger.info(
            "Associations for allocation %s and users %s have been removed",
            allocation,
            stale_users,
        )
