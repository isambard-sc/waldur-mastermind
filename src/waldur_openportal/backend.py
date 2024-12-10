import logging
import operator
from functools import reduce

from django.conf import settings as django_settings
from django.db import transaction
from django.utils import timezone

from waldur_core.structure.backend import ServiceBackend
from waldur_core.structure.exceptions import ServiceBackendError
from waldur_freeipa import models as freeipa_models
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

    def sync_users(self, allocation):
        logger.info(f"Syncing users for allocation: {allocation}")
        users = allocation.project.get_users()
        logger.info(f"Users for allocation: {users}")
        profiles = freeipa_models.Profile.objects.filter(user__in=users)
        for profile in profiles:
            logger.info(f"Adding user {profile.username} to allocation {allocation}")
            succeeded = self.add_user(
                allocation, profile.user, profile.username.lower()
            )
            if succeeded:
                models.Association.objects.get_or_create(
                    allocation=allocation,
                    username=profile.username,
                )

        all_backend_usernames = self.client.list_account_users(allocation.backend_id)
        backend_usernames = freeipa_models.Profile.objects.filter(
            username__in=all_backend_usernames
        ).values_list("username", flat=True)
        local_usernames = [profile.username for profile in profiles]
        stale_usernames = set(backend_usernames) - set(local_usernames)

        for profile in freeipa_models.Profile.objects.filter(
            username__in=stale_usernames
        ):
            username = profile.username.lower()
            logger.info(f"Deleting user {username} from allocation {allocation}")
            succeeded = self.delete_user(allocation, profile.user, username)
            if succeeded:
                try:
                    models.Association.objects.get(
                        allocation=allocation, username=username
                    ).delete()
                    logger.info(
                        "Association between %s and %s has been deleted",
                        allocation,
                        profile.user,
                    )
                except models.Association.DoesNotExist:
                    logger.warn(
                        "Association between %s and %s has been already deleted",
                        allocation,
                        profile.user,
                    )

    def create_allocation(self, allocation):
        logger.info(f"Creating allocation: {allocation}")
        project = allocation.project
        customer_account = self.get_customer_name(project.customer)
        project_account = self.get_project_name(project)
        allocation_account = self.get_allocation_name(allocation)

        if not self.client.get_account(customer_account):
            self.create_customer(project.customer)

        if not self.client.get_account(project_account):
            self.create_project(project)

        self.client.create_account(
            name=allocation_account,
            description=allocation.name,
            organization=project_account,
        )
        allocation.backend_id = allocation_account

        default_limits = django_settings.WALDUR_OPENPORTAL["DEFAULT_LIMITS"]
        allocation.cpu_limit = default_limits["CPU"]
        allocation.gpu_limit = default_limits["GPU"]
        allocation.ram_limit = default_limits["RAM"]
        allocation.save()

        self.set_resource_limits(allocation)
        self.sync_users(allocation)

    def delete_allocation(self, allocation):
        logger.info(f"Deleting allocation: {allocation}")
        account = allocation.backend_id

        if not account.strip():
            raise ServiceBackendError(
                "Empty backend_id for allocation: %s" % allocation
            )

        if self.client.get_account(account):
            self.client.delete_account(account)

        project = allocation.project
        if self.get_allocation_queryset().filter(project=project).count() == 0:
            self.delete_project(project)

        if (
            self.get_allocation_queryset()
            .filter(project__customer=project.customer)
            .count()
            == 0
        ):
            self.delete_customer(project.customer)

    def add_user(self, allocation, user, username):
        """
        Create association between user and OpenPortal account if it does not exist yet.
        """
        logger.info(f"Adding OpenPortal user {username} to allocation {allocation}")
        account = allocation.backend_id

        if not account.strip():
            raise ServiceBackendError(
                "Empty backend_id for allocation: %s" % allocation
            )

        default_account = self.settings.options.get("default_account")
        if not self.client.get_association(username, account):
            logger.info("Creating association between %s and %s", username, account)
            try:
                self.client.create_association(username, account, default_account)
                signals.openportal_association_created.send(
                    models.Allocation,
                    allocation=allocation,
                    user=user,
                    username=username,
                )
            except base.BatchError as err:
                logger.error("Unable to create association in OpenPortal: %s", err)
                return False
        return True

    def delete_user(self, allocation, user, username):
        """
        Delete association between user and OpenPortal account if it exists.
        """
        logger.info(f"Deleting OpenPortal user {username} from allocation {allocation}")
        account = allocation.backend_id

        if not account.strip():
            raise ServiceBackendError(
                "Empty backend_id for allocation: %s" % allocation
            )

        if self.client.get_association(username, account):
            logger.info("Deleting association between %s and %s", username, account)
            try:
                self.client.delete_association(username, account)
                signals.openportal_association_deleted.send(
                    models.Allocation, allocation=allocation, user=user
                )
            except base.BatchError as err:
                logger.error("Unable to delete association in OpenPortal: %s", err)
                return False
        return True

    def set_resource_limits(self, allocation: models.Allocation):
        # TODO: add default limits configuration (https://opennode.atlassian.net/browse/WAL-3037)
        logger.info(f"Setting resource limits for allocation {allocation}")
        limits = Quotas(
            cpu=allocation.cpu_limit,
            gpu=allocation.gpu_limit,
            ram=allocation.ram_limit,
        )
        self.client.set_resource_limits(allocation.backend_id, limits)

    def sync_usage(self):
        logger.info(f"Syncing OpenPortal usage for settings: {self}")
        waldur_allocations = {
            allocation.backend_id: allocation
            for allocation in self.get_allocation_queryset()
            if allocation.backend_id
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
        account = allocation.backend_id

        if not account.strip():
            raise ServiceBackendError(
                "Empty backend_id for allocation: %s" % allocation
            )

        report = self.get_usage_report([account])
        usage = report.get(account)
        if not usage:
            usage = {"TOTAL_ACCOUNT_USAGE": Quotas()}
        self._update_quotas(allocation, usage)
        limits = self.get_allocation_limits(account)
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
                user_usage.cpu = round(user_usage.cpu)
                user_usage.gpu = round(user_usage.gpu)
                user_usage.ram = round(user_usage.ram)
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
            limits = Quotas(cpu=line.cpu, gpu=line.gpu, ram=line.ram)
            return limits

    def _update_limits(self, allocation, limits):
        logger.info(f"Updating limits for OpenPortal allocation {allocation}")
        if not limits:
            return
        allocation.cpu_limit = limits.cpu
        allocation.gpu_limit = limits.gpu
        allocation.ram_limit = limits.ram
        allocation.save(update_fields=["cpu_limit", "gpu_limit", "ram_limit"])

    @transaction.atomic()
    def _update_quotas(self, allocation, usage):
        logger.info(f"Updating quotas for OpenPortal allocation {allocation} for usage {usage}")
        quotas = usage.pop("TOTAL_ACCOUNT_USAGE")
        allocation.cpu_usage = quotas.cpu
        allocation.gpu_usage = quotas.gpu
        allocation.ram_usage = quotas.ram
        allocation.save(update_fields=["cpu_usage", "gpu_usage", "ram_usage"])

        usernames = usage.keys()
        usermap = {
            profile.username: profile.user
            for profile in freeipa_models.Profile.objects.filter(username__in=usernames)
        }

        for username, quotas in usage.items():
            models.AllocationUserUsage.objects.update_or_create(
                allocation=allocation,
                year=timezone.now().year,
                month=timezone.now().month,
                user=usermap.get(username),
                username=username,
                defaults={
                    "cpu_usage": quotas.cpu,
                    "gpu_usage": quotas.gpu,
                    "ram_usage": quotas.ram,
                },
            )

    def create_customer(self, customer):
        logger.info(f"Creating OpenPortal customer {customer}")
        customer_name = self.get_customer_name(customer)
        return self.client.create_account(customer_name, customer.name, customer_name)

    def delete_customer(self, customer_uuid):
        logger.info(f"Deleting OpenPortal customer {customer_uuid}")
        self.client.delete_account(self.get_customer_name(customer_uuid))

    def create_project(self, project):
        logger.info(f"Creating OpenPortal project {project}")
        name = self.get_project_name(project)
        parent_name = self.get_customer_name(project.customer)
        return self.client.create_account(name, project.name, name, parent_name)

    def delete_project(self, project_uuid):
        logger.info(f"Deleting OpenPortal project {project_uuid}")
        self.client.delete_account(self.get_project_name(project_uuid))

    def get_allocation_queryset(self):
        logger.info("Getting OpenPortal allocation queryset")
        return models.Allocation.objects.filter(service_settings=self.settings)

    def get_customer_name(self, customer):
        logger.info(f"Getting OpenPortal customer name for customer {customer}")
        return self.get_account_name(
            django_settings.WALDUR_OPENPORTAL["CUSTOMER_PREFIX"], customer
        )

    def get_project_name(self, project):
        logger.info(f"Getting OpenPortal project name for project {project}")
        return self.get_account_name(
            django_settings.WALDUR_OPENPORTAL["PROJECT_PREFIX"], project
        )

    def get_allocation_name(self, allocation):
        logger.info(f"Getting OpenPortal allocation name for allocation {allocation}")
        prefix = django_settings.WALDUR_OPENPORTAL["ALLOCATION_PREFIX"]
        name = allocation.name
        hexpart = allocation.uuid.hex[:5]
        raw_name = f"{prefix}{hexpart}_{name}"
        result_name = sanitize_allocation_name(raw_name)[
            : models.OPENPORTAL_ALLOCATION_NAME_MAX_LEN
        ]
        return result_name.lower()

    def get_account_name(self, prefix, object_or_uuid):
        logger.info(f"Getting OpenPortal account name for object {object_or_uuid}")
        key = (
            isinstance(object_or_uuid, str)
            and object_or_uuid
            or object_or_uuid.uuid.hex
        )
        return f"{prefix}{key}"

    def _update_allocation_associations(self, allocation):
        logger.info(f"Updating associations for allocation {allocation}")
        backend_usernames = self.client.list_account_users(allocation.backend_id)

        local_usernames = [
            association.username for association in allocation.associations.all()
        ]
        stale_usernames = set(local_usernames) - set(backend_usernames)
        models.Association.objects.filter(
            allocation=allocation, username__in=stale_usernames
        ).delete()

        logger.info(
            "Associations for allocation %s and users %s have been removed",
            allocation,
            stale_usernames,
        )

        new_usernames = set(backend_usernames) - set(local_usernames)

        for username in new_usernames:
            models.Association.objects.create(
                allocation=allocation,
                username=username,
            )
