import logging

from waldur_core.core import models as core_models
from waldur_core.core import tasks as core_tasks
from waldur_core.core import utils as core_utils
from waldur_core.structure import filters as structure_filters
from waldur_core.structure import models as structure_models
from waldur_core.structure import permissions as structure_permissions
from waldur_openstack.openstack import apps

from .log import event_logger
from .models import Tenant

logger = logging.getLogger(__name__)


def remove_ssh_key_from_tenants(sender, instance, **kwargs):
    """Delete user ssh keys from tenants that he does not have access now."""
    tenants = Tenant.objects.all()
    if isinstance(instance.scope, structure_models.Customer):
        tenants = tenants.filter(project__customer=instance.scope)
    elif isinstance(instance.scope, structure_models.Project):
        tenants = tenants.filter(project=instance.scope)
    else:
        return
    ssh_keys = core_models.SshPublicKey.objects.filter(user=instance.user)
    for tenant in tenants:
        if structure_permissions._has_admin_access(instance.user, tenant.project):
            continue  # no need to delete ssh keys if user still have permissions for tenant.
        serialized_tenant = core_utils.serialize_instance(tenant)
        key: core_models.SshPublicKey
        for key in ssh_keys:
            core_tasks.BackendMethodTask().delay(
                serialized_tenant,
                "remove_ssh_key_from_tenant",
                key.name,
                key.fingerprint_md5,
            )


def remove_ssh_key_from_all_tenants_on_it_deletion(sender, instance, **kwargs):
    """Delete key from all tenants that are accessible for user on key deletion."""
    ssh_key: core_models.SshPublicKey = instance
    user = ssh_key.user
    tenants = structure_filters.filter_queryset_for_user(Tenant.objects.all(), user)
    for tenant in tenants:
        if not structure_permissions._has_admin_access(user, tenant.project):
            continue
        serialized_tenant = core_utils.serialize_instance(tenant)
        core_tasks.BackendMethodTask().delay(
            serialized_tenant,
            "remove_ssh_key_from_tenant",
            ssh_key.name,
            ssh_key.fingerprint_md5,
        )


def log_tenant_quota_update(sender, instance, created=False, **kwargs):
    quota = instance
    if created or not isinstance(quota.scope, Tenant):
        return

    if not quota.tracker.has_changed("value"):
        return

    tenant = quota.scope
    new_value_representation = quota.scope.format_quota(quota.name, quota.value)
    old_value_representation = quota.scope.format_quota(
        quota.name, quota.tracker.previous("value")
    )
    event_logger.openstack_tenant_quota.info(
        f"{{quota_name}} quota limit has been changed from {old_value_representation} to {new_value_representation} for tenant {{tenant_name}}.",
        event_type="openstack_tenant_quota_limit_updated",
        event_context={
            "quota_name": quota.name,
            "tenant": tenant,
            "limit": quota.value,
            "old_limit": quota.tracker.previous("value"),
        },
    )


def update_service_settings_name(sender, instance, created=False, **kwargs):
    tenant = instance

    if created or not tenant.tracker.has_changed("name"):
        return

    try:
        service_settings = structure_models.ServiceSettings.objects.get(
            scope=tenant, type=apps.OpenStackConfig.service_name
        )
    except structure_models.ServiceSettings.DoesNotExist:
        return
    else:
        service_settings.name = tenant.name
        service_settings.save()


def log_security_group_cleaned(sender, instance, **kwargs):
    event_logger.openstack_security_group.info(
        "Security group %s has been cleaned from cache." % instance.name,
        event_type="openstack_security_group_cleaned",
        event_context={
            "security_group": instance,
        },
    )


def log_security_group_rule_cleaned(sender, instance, **kwargs):
    event_logger.openstack_security_group_rule.info(
        "Security group rule %s has been cleaned from cache." % str(instance),
        event_type="openstack_security_group_rule_cleaned",
        event_context={
            "security_group_rule": instance,
        },
    )


def log_network_cleaned(sender, instance, **kwargs):
    event_logger.openstack_network.info(
        "Network %s has been cleaned from cache." % instance.name,
        event_type="openstack_network_cleaned",
        event_context={
            "network": instance,
        },
    )


def log_subnet_cleaned(sender, instance, **kwargs):
    event_logger.openstack_subnet.info(
        "SubNet %s has been cleaned." % instance.name,
        event_type="openstack_subnet_cleaned",
        event_context={
            "subnet": instance,
        },
    )


def log_server_group_cleaned(sender, instance, **kwargs):
    event_logger.openstack_server_group.info(
        "Server group %s has been cleaned from cache." % instance.name,
        event_type="openstack_server_group_cleaned",
        event_context={
            "server_group": instance,
        },
    )
