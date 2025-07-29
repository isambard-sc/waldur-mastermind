import logging
import functools

from django.conf import settings
from django.db import transaction
from django.db.models import Sum

from waldur_core.core import utils as core_utils
from waldur_core.core.models import User
from waldur_core.permissions.models import UserRole
from waldur_core.structure.models import Customer, Project
from waldur_mastermind.marketplace import models as marketplace_models

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
    """
    Schedule a synchronization of OpenPortal data. This will double-check
    that all users are correctly associated with all projects and
    instances, and will add/remove users as needed
    """
    logger.info("Scheduling OpenPortal synchronization.")

    # We will rate-limit by synchronizing only once per transaction.
    # This is useful for when multiple changes are made in a single transaction,
    # such as when a user is created and then immediately added to a project.
    if transaction.get_connection().in_atomic_block:
        logger.info("OpenPortal synchronization already scheduled in this transaction.")
        return

    transaction.on_commit(lambda: tasks.sync.delay())


@if_plugin_enabled
def schedule_deletion_sync(*args, **kwargs):
    """
    Schedule a synchronization of OpenPortal data after a project or
    customer is deleted. This will double-check that all users are correctly
    associated with the project/customer, and will remove users as needed.
    """
    logger.info("[TODO] Scheduling OpenPortal synchronization after deletion.")


@if_plugin_enabled
def schedule_project_sync(project):
    """
    Schedule a synchronization of OpenPortal data for a specific project.
    This will double-check that all users are correctly associated with
    the project, and will add/remove users as needed
    """

    logger.info(f"Scheduling OpenPortal synchronization for project {project}")
    transaction.on_commit(
        lambda: tasks.sync_project.delay(core_utils.serialize_instance(project))
    )


@if_plugin_enabled
def schedule_sync_on_quota_change(sender, instance, created=False, **kwargs):
    if instance.name != utils.QUOTA_NAME:
        return
    if created and instance.value == -1:
        return

    transaction.on_commit(schedule_sync)


@if_plugin_enabled
def update_allocation_credits(sender, instance, **kwargs):
    """
    Update the allocation credits for the given resource. This is called
    when a resource is created or updated, and will ensure that the
    allocation credits are correctly set in OpenPortal.
    """
    resource = instance

    if not isinstance(resource, marketplace_models.Resource):
        logger.error(
            f"OpenPortal - {resource} is not a Resource instance - it is {type(resource)}"
        )
        return

    # Check to see if there is a remote allocation associated with this resource
    uuid = str(resource.uuid)

    for remote_allocation in models.RemoteAllocation.objects.filter(is_active=True):
        if remote_allocation.marketplace_uuid == uuid:
            project = remote_allocation.project

            if not project.is_expired or project.is_removed:
                logger.info(f"OpenPortal - updating project {project}")

                transaction.on_commit(
                    lambda: tasks.update_remote_project.delay(
                        core_utils.serialize_instance(project)
                    )
                )


@if_plugin_enabled
def update_project(sender, instance, force_add=False, **kwargs):
    """
    Update the project (passed as "instance") in OpenPortal. If this
    is a remote project, then it will send the OpenPortal remote
    commands to update the project in the remote portal
    """
    project = instance

    if force_add or set(project.tracker.changed()) & {
        "name",
        "description",
        "start_date",
        "end_date",
    }:
        # check to see if there are any remote allocations associated
        # with this project
        remote_allocations = models.RemoteAllocation.objects.filter(
            project=project,
        )

        if not remote_allocations.exists():
            # nothing to do
            return

        # Either the project's name or description has changed, or the
        # project has just been added to the user - we need to update the
        # project (updating is the same as adding in OpenPortal)
        logger.info(f"OpenPortal - updating project {project}")

        transaction.on_commit(
            lambda: tasks.update_remote_project.delay(
                core_utils.serialize_instance(project)
            )
        )


@if_plugin_enabled
def delete_project(sender, instance, **kwargs):
    """
    Make sure to remote the project in the remote portal if it is
    deleted from the top portal
    """
    project = instance

    # check to see if there are any remote allocations associated
    remote_allocations = models.RemoteAllocation.objects.filter(
        project=project,
    )

    if remote_allocations.exists():
        transaction.on_commit(
            lambda: tasks.delete_remote_project.delay(
                core_utils.serialize_instance(project)
            )
        )

    # Also make sure that any connected managed project is marked as needing approval.
    # This ensures that the site admin will be aware of the deletion and
    # will need to approve any further changes.
    managed_projects = models.ManagedProject.objects.filter(project=project)

    for managed_project in managed_projects:
        managed_project.set_needs_approval(
            True,
            comment="Attached project was deleted.",
        )
        managed_project.project = None
        managed_project.save(update_fields=["project"])
        logger.info(
            f"ManagedProject {managed_project.identifier} marked as needing approval "
            f"due to deletion of attached project: {project}"
        )


@if_plugin_enabled
def update_user(sender, instance, force_add=False, **kwargs):
    """
    Update the user (passed as "instance") in OpenPortal. This will
    look for all associations between the user and all projects and
    will add the user to each of those projects.
    """

    user = instance

    if force_add or set(user.tracker.changed()) & {"unix_username"}:
        # Either the user's unix_username has changed, or the user has
        # just been added to the project - we need to update the user
        # (updating is the same as adding in OpenPortal)
        logger.info(f"OpenPortal - updating user {user}")

        # check if this is a User type
        if not isinstance(user, User):
            logger.error(
                f"OpenPortal - {user} is not a User instance - it is {type(user)}"
            )
            return

        transaction.on_commit(
            lambda: tasks.update_user.delay(core_utils.serialize_instance(user))
        )


@if_plugin_enabled
def delete_user(sender, instance, **kwargs):
    """
    Completely delete the user from all OpenPortal allocations to which
    they are allocated. This is called when a user is completely deleted
    from Waldur. It should not be used to remove a user from an individual
    project. Instead, schedule a sync, and the sync will remove all users
    who are incorrectly still associated with projects.
    """
    user = instance

    if not isinstance(instance, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    transaction.on_commit(
        lambda: tasks.delete_user.delay(core_utils.serialize_instance(instance))
    )


@if_plugin_enabled
def role_granted(sender, instance: UserRole, **kwargs):
    """
    This function is called when a user is granted a role in a project.
    The instance should by a UserRole. Note that this will trigger
    an `update_user` for the user, which will ensure that the user
    is correctly added to all projects to which they should have access.
    """
    logger.info(
        f"OpenPortal - granting role {instance.role} for user {instance.user} in {instance.scope}"
    )

    user = instance.user

    if not isinstance(user, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    if not user.is_active:
        logger.warning(
            f"Cannot synchronize role {instance.role} for user {instance.user} as user is not active."
        )
        return

    # Skip synchronization of custom roles
    if not instance.role.is_system_role:
        logger.warning(f"{instance.role} is not a system role - synchronising anyway")

    if not instance.role.is_active:
        logger.warning(
            f"Cannot synchronize role {instance.role} for user {instance.user} as role is not active."
        )
        return

    if not isinstance(instance.scope, Customer | Project):
        logger.warning(f"Skipping as {instance.scope} is not a Customer or Project")
        return

    # let's just update the user...
    logger.info(
        f"Really sending update_user({sender}, {user}, force_add=True, **{kwargs})"
    )
    update_user(sender, user, force_add=True, **kwargs)


@if_plugin_enabled
def role_revoked(sender, instance, **kwargs):
    """
    Revoke a role from the passed user. Note that this will trigger a full
    OpenPortal synchronization, which will ensure that all users are
    removed from projects from which they are not allocated.
    """
    logger.info(
        f"OpenPortal - revoking role {instance.role} for user {instance.user} in {instance.scope}"
    )

    # Skip synchronization of custom roles
    if not instance.role.is_system_role:
        logger.warning(f"{instance.role} is not a system role - synchronising anyway")

    if not isinstance(instance.scope, Customer | Project):
        logger.warning(f"Skipping as {instance.scope} is not a Customer or Project")
        return

    # re-sync everyone in the project - this is safe as it will catch
    # people who should have been removed previously too
    schedule_project_sync(instance.scope)


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


@if_plugin_enabled
def update_quotas_on_remote_allocation_usage_update(
    sender, instance, created=False, **kwargs
):
    if created:
        return

    allocation = instance
    if not allocation.usage_changed():
        return

    project = allocation.project
    update_remote_quotas(project, models.RemoteAllocation.Permissions.project_path)
    update_remote_quotas(
        project.customer, models.RemoteAllocation.Permissions.customer_path
    )


def update_quotas(scope, path):
    qs = models.Allocation.objects.filter(**{path: scope}).values(path)
    for quota in utils.FIELD_NAMES:
        qs = qs.annotate(**{"total_%s" % quota: Sum(quota)})
    qs = list(qs)[0]

    for quota in utils.FIELD_NAMES:
        scope.set_quota_usage(utils.MAPPING[quota], qs["total_%s" % quota])


def update_remote_quotas(scope, path):
    qs = models.RemoteAllocation.objects.filter(**{path: scope}).values(path)
    for quota in utils.FIELD_NAMES:
        qs = qs.annotate(**{"total_%s" % quota: Sum(quota)})
    qs = list(qs)[0]

    for quota in utils.FIELD_NAMES:
        scope.set_quota_usage(utils.MAPPING[quota], qs["total_%s" % quota])
