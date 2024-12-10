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

    def get_op_user_name(self, user):
        """
        Return the username that OpenPortal uses for the passed user.
        Returns None if the user is not in OpenPortal.
        """
        try:
            association = models.Association.objects.get(user=user)
            return association.username
        except models.Association.DoesNotExist:
            return None

    def sync_users(self, allocation):
        logger.info(f"Syncing users for allocation: {allocation}")
        op_project_name = allocation.op_project_name()
        users = allocation.project.get_users()
        logger.info(f"Users for allocation: {users}")

        # list all users who OpenPortal thinks are in the project
        op_user_names = self.client.get_users(op_project_name=op_project_name)

        allocation_user_names = []

        # go through and add the users who are not in OpenPortal
        for user in users:
            op_user_name = self.get_op_user_name(user)

            if op_user_name is None or op_user_name not in op_user_names:
                logger.info(f"Adding user {user} to OpenPortal")
                unix_shortname = self.get_user_short_name(user)
                op_user_name = self.client.add_user(name=unix_shortname, op_project_name=op_project_name)

                models.Association.objects.get_or_create(
                    allocation=allocation,
                    username=username
                )

            allocation_user_names.append(op_user_name)

        stale_op_user_names = set(op_user_names) - set(allocation_user_names)

        for username in stale_op_user_names:
            self.client.delete_user(username)

    def create_allocation(self, allocation):
        logger.info(f"Creating allocation: {allocation}")
        project = allocation.project
        project_name = self.get_project_short_name(project)

        logger.info(f"Details: {project} : {project_name}")

        op_project_name = self.client.add_project(project_name)

        logger.info(f"Created project: {op_project_name}")

        allocation.backend_id = op_project_name

        allocation.node_limit = 0
        allocation.save()

        self.set_resource_limits(allocation)
        self.sync_users(allocation)

    def delete_allocation(self, allocation):
        logger.info(f"Deleting allocation: {allocation}")
        op_project_name = allocation.op_project_name()

        if not op_project_name.strip():
            raise ServiceBackendError(
                "Empty op_project_name for allocation: %s" % allocation
            )

        self.client.delete_project(op_project_name)

        project = allocation.project
        if self.get_allocation_queryset().filter(project=project).count() == 0:
            self.delete_project(project)

    def add_user(self, allocation, user):
        """
        Create association between user and OpenPortal account if it does not exist yet.
        """
        logger.info(f"Adding user {user} to allocation {allocation} in OpenPortal")
        op_project_name = allocation.op_project_name()

        if not op_project_name.strip():
            raise ServiceBackendError(
                "Empty op_project_name for allocation: %s" % allocation
            )

        unix_shortname = self.get_user_short_name(user)

        try:
            op_user_name = self.client.add_user(unix_shortname, op_project_name)

            signals.openportal_association_created.send(
                models.Allocation,
                allocation=allocation,
                user=user,
                username=op_user_name,
            )
        except Exception as e:
            logger.error("Unable to create association in OpenPortal: %s", e)
            return False

        return True

    def delete_user(self, allocation, user):
        """
        Delete association between user and OpenPortal account if it exists.
        """
        logger.info(f"Deleting OpenPortal user {user} from allocation {allocation}")
        op_project_name = allocation.op_project_name()

        if not op_project_name.strip():
            raise ServiceBackendError(
                "Empty op_project_name for allocation: %s" % allocation
            )

        op_user_name = self.get_op_user_name(user)

        if op_user_name is not None:
            logger.info(f"Deleting user {op_user_name} from OpenPortal")
            self.client.delete_user(op_user_name)

            signals.openportal_association_deleted.send(
                models.Allocation, allocation=allocation, user=user, username=op_user_name
            )

            return True
        else:
            return False

    def set_resource_limits(self, allocation: models.Allocation):
        logger.info(f"Setting resource limits for allocation {allocation}")
        limits = Quotas(
            node=allocation.node_limit,
        )
        self.client.set_resource_limits(allocation.op_project_name(), limits)

    def sync_usage(self):
        logger.info(f"Syncing OpenPortal usage for settings: {self}")
        waldur_allocations = {
            allocation.op_project_name(): allocation
            for allocation in self.get_allocation_queryset()
            if allocation.op_project_name()
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

    def pull_allocation(self, allocation):
        logger.info(f"Pulling OpenPortal allocation {allocation}")
        self.sync_users(allocation)
        op_project_name = allocation.op_project_name()

        if not op_project_name.strip():
            raise ServiceBackendError(
                "Empty op_project_name for allocation: %s" % allocation
            )

        report = self.get_usage_report([op_project_name])
        usage = report.get(op_project_name)
        if not usage:
            usage = {"TOTAL_ACCOUNT_USAGE": Quotas()}
        self._update_quotas(allocation, usage)
        limits = self.get_allocation_limits(op_project_name)
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
        logger.info(f"Updating associations for allocation {allocation}")
        op_user_names = self.client.get_users(allocation.op_project_name())

        local_usernames = [
            association.username for association in allocation.associations.all()
        ]
        stale_usernames = set(local_usernames) - set(op_user_names)
        models.Association.objects.filter(
            allocation=allocation, username__in=stale_usernames
        ).delete()

        logger.info(
            "Associations for allocation %s and users %s have been removed",
            allocation,
            stale_usernames,
        )

        new_usernames = set(op_user_names) - set(local_usernames)

        # where is this getting the user for the association?
        for username in new_usernames:
            models.Association.objects.create(
                allocation=allocation,
                username=username,
            )
