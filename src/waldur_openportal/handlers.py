import logging
import functools

from django.conf import settings
from django.db import transaction
from django.db.models import Sum

from waldur_core.core import utils as core_utils
from waldur_core.core.models import User
from waldur_core.permissions.models import UserRole
from waldur_core.structure.models import Customer, Project

from . import models, tasks, utils

logger = logging.getLogger(__name__)


def if_plugin_enabled(f):
    """Calls decorated handler only if plugin is enabled."""

    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if settings.WALDUR_OPENPORTAL["ENABLED"]:
            return f(*args, **kwargs)
        else:
            logger.info("Skipping OpenPortal handler because plugin is disabled.")

    return wrapped


@if_plugin_enabled
def schedule_sync(*args, **kwargs):
    logger.info("Scheduling OpenPortal synchronization.")
    tasks.schedule_sync()


@if_plugin_enabled
def schedule_sync_on_quota_change(sender, instance, created=False, **kwargs):
    if instance.name != utils.QUOTA_NAME:
        return
    if created and instance.value == -1:
        return

    transaction.on_commit(schedule_sync)


@if_plugin_enabled
def update_user(sender, instance, created=False, **kwargs):
    user = instance

    logger.info(f"OpenPortal - updating user {user}")

    # check if this is a User type
    if not isinstance(user, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    transaction.on_commit(
        lambda: tasks.update_user.delay(core_utils.serialize_instance(user))
    )

@if_plugin_enabled
def delete_user(sender, instance, **kwargs):
    user = instance
    logger.info(f"OpenPortal - deleting user {user}")

    if not isinstance(instance, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    transaction.on_commit(
        lambda: tasks.delete_user.delay(core_utils.serialize_instance(instance))
    )


@if_plugin_enabled
def role_granted(sender, instance: UserRole, **kwargs):
    logger.info(f"OpenPortal - granting role {instance.role} for user {instance.user} in {instance.scope}")

    user = instance.user

    if not isinstance(user, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    # Skip synchronization of custom roles
    if not instance.role.is_system_role:
        logger.warning(f"Cannot synchronize custom role {instance.role} for user {instance.user} as not a system role.")
        return

    if not instance.role.is_active:
        logger.warning(f"Cannot synchronize role {instance.role} for user {instance.user} as role is not active.")
        return

    if not isinstance(instance.scope, Customer | Project):
        return

    # let's just update the user...
    logger.info(f"Really sending update_user({sender}, {user}, created=True, **{kwargs})")
    update_user(sender, user, created=True, **kwargs)


@if_plugin_enabled
def role_revoked(sender, instance, **kwargs):
    logger.info(f"OpenPortal - revoking role {instance.role} for user {instance.user} in {instance.scope}")

    # Skip synchronization of custom roles
    if not instance.role.is_system_role:
        return

    if not isinstance(instance.scope, Customer | Project):
        return

    # re-sync everything - it's safer, but could be optimised
    schedule_sync()


@if_plugin_enabled
def update_quotas_on_allocation_usage_update(sender, instance, created=False, **kwargs):
    if created:
        return

    allocation = instance
    if not allocation.usage_changed():
        return

    project = allocation.project
    update_quotas(project, models.Allocation.Permissions.project_path)
    update_quotas(project.customer, models.Allocation.Permissions.customer_path)


def update_quotas(scope, path):
    qs = models.Allocation.objects.filter(**{path: scope}).values(path)
    for quota in utils.FIELD_NAMES:
        qs = qs.annotate(**{"total_%s" % quota: Sum(quota)})
    qs = list(qs)[0]

    for quota in utils.FIELD_NAMES:
        scope.set_quota_usage(utils.MAPPING[quota], qs["total_%s" % quota])
