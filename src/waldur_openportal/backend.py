
import logging
import operator
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
            self.sync_usage()

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

    def get_project_short_name(self, project):
        """
        Return the preferred short name for the passed project.
        """
        return project.short_name

    def get_user_short_name(self, user):
        """
        Return the preferred short name for the passed user.
        """
        return user.unix_username

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

                logger.info(f"Association: {association}")

                mapping = None

                if association.has_mapping():
                    mapping = association.get_mapping()

                if mapping is None or mapping not in user_mappings:
                    logger.info(f"Adding user {user} to OpenPortal")
                    shortname = self.get_user_short_name(user)

                    if shortname is None or not shortname.strip():
                        logger.error(f"Empty unix_shortname for user: {user} - cannot add to OpenPortal")
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

        logger.info(f"Stale users in OpenPortal: {stale_mappings}")

        for mapping in stale_mappings:
            try:
                self.client.delete_user(mapping.user)
                # no need to signal as the user has already been removed from the association
            except Exception as e:
                logger.error(f"Unable to delete user with mapping {mapping} from OpenPortal: {e}")

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
            project = allocation.project
            project_name = self.get_project_short_name(project)
            logger.info(f"Creating allocation: {allocation} for project {project_name}")

            if project_name is None or not project_name.strip():
                logger.error(f"Empty project_name for allocation: {allocation} - cannot create in OpenPortal")
                return

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

        shortname = self.get_user_short_name(user)

        if shortname is None or not shortname.strip():
            logger.error(f"Empty unix_shortname for user: {user} - they cannot be added to OpenPortal")
            return False

        # get or create the association between the user and the allocation
        # This association holds the username of the user in OpenPortal on this instance
        (association, created) = models.Association.objects.get_or_create(user=user, allocation=allocation)

        mapping = None

        if association.has_mapping():
            mapping = association.get_mapping()

        if mapping is not None:
            logger.info(f"User {user} hasd previously been in {project} with mapping {mapping}")
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

    def sync_usage(self):
        logger.info(f"Syncing OpenPortal usage for settings: {self}")
        waldur_allocations = {
            allocation.get_project_identifier(): allocation
            for allocation in self.get_allocation_queryset()
            if allocation.has_project_identifier()
        }

        report = self.get_usage_report(waldur_allocations.keys())
        for account, usage in report.items():
            allocation = waldur_allocations.get(account)
            if not allocation:
                logger.info(
                    "Skipping usage report for account %s because it is not managed under Waldur",
                    account,
                )
                continue
            self._update_quotas(allocation, usage)

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

        project = allocation.get_project_identifier()

        report = self.get_usage_report([project])
        usage = report.get(project)
        if not usage:
            usage = {"TOTAL_ACCOUNT_USAGE": Quotas()}
        self._update_quotas(allocation, usage)
        limits = self.get_allocation_limits(project)
        self._update_limits(allocation, limits)

    def get_usage_report(self, accounts):
        logger.info(f"Getting OpenPortal usage report for accounts: {accounts}")
        report = {}
        lines = self.client.get_usage_report(accounts)

        for line in lines:
            report.setdefault(line.account, {}).setdefault(line.user, Quotas())
            report[line.account][line.user] += line.quotas

        for usage in report.values():
            for user_usage in usage.values():
                user_usage.node = round(user_usage.node)
            quotas = usage.values()
            total = reduce(operator.add, quotas)
            usage["TOTAL_ACCOUNT_USAGE"] = total

        return report

    def get_allocation_limits(self, account):
        logger.info(f"Getting OpenPortal limits for account: {account}")
        lines = self.client.get_resource_limits(account)
        correct_lines = [
            association for association in lines if association.resource_limits
        ]
        if len(correct_lines) > 0:
            line = correct_lines[0]
            limits = Quotas(node=line.node)
            return limits

    def _update_limits(self, allocation, limits):
        logger.info(f"Updating limits for OpenPortal allocation {allocation}")
        if not limits:
            return
        allocation.node_limit = limits.node
        allocation.save(update_fields=["node_limit"])

    @transaction.atomic()
    def _update_quotas(self, allocation, usage):
        logger.info(f"Updating quotas for OpenPortal allocation {allocation} for usage {usage}")
        quotas = usage.pop("TOTAL_ACCOUNT_USAGE")
        allocation.node_usage = quotas.node
        allocation.save(update_fields=["node_usage"])

        usernames = usage.keys()

        usermap = {
            association.username: association.user
            for association in models.Association.objects.filter(username__in=usernames)
        }

        for username, quotas in usage.items():
            models.AllocationUserUsage.objects.update_or_create(
                allocation=allocation,
                year=timezone.now().year,
                month=timezone.now().month,
                user=usermap.get(username, None),
                username=username,
                defaults={
                    "node_usage": quotas.node,
                },
            )

    def get_allocation_queryset(self):
        logger.info("Getting OpenPortal allocation queryset")
        return models.Allocation.objects.filter(service_settings=self.settings)

    def _update_allocation_associations(self, allocation):
        logger.info(f"OpenPortal NoOp - Updating associations for allocation {allocation}")
