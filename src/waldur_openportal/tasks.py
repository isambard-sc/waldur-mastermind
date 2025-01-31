import logging

from celery import shared_task

from waldur_core.core import utils as core_utils
from waldur_core.core.models import User
from waldur_core.structure import models as structure_models

from . import backend, models, utils


logger = logging.getLogger(__name__)


def get_structure_allocations(structure):
    """
    Return all of the allocations associated with the passed object
    """
    if isinstance(structure, structure_models.Project):
        return list(models.Allocation.objects.filter(is_active=True, project=structure))
    elif isinstance(structure, structure_models.Customer):
        return list(
            models.Allocation.objects.filter(
                is_active=True, project__customer=structure
            )
        )
    else:
        return []


@shared_task(name="waldur_openportal.add_allocated_project")
def add_allocated_project(serialized_allocation):
    """
    Add the allocated project to the OpenPortal backend
    """
    logger.info(f"task.add_allocated_project: {serialized_allocation}")
    allocation = core_utils.deserialize_instance(serialized_allocation)

    openportal_backend: backend.OpenPortalBackend = allocation.get_backend()
    openportal_backend.add_allocated_project(allocation)


@shared_task(name="waldur_openportal.update_user")
def update_user(serialized_user):
    """
    Update the user by making sure that they are added to all OpenPortal
    resources to which they have allocations.
    """
    logger.info(f"task.update_user: {serialized_user}")
    user = core_utils.deserialize_instance(serialized_user)

    if not isinstance(user, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    for allocation in utils.get_project_allocations(user):
        # adding and updating are the same thing in OpenPortal
        backend = allocation.get_backend()

        if not allocation.is_added_to_openportal():
            allocation = backend.add_allocated_project(allocation)

        if not (
            allocation.has_project_identifier() or allocation.is_added_to_openportal()
        ):
            logger.warning(
                f"Cannot add {user} to {allocation} as it is not in OpenPortal - skipping"
            )
            continue

        logger.info(
            f"Adding user {user} to project {allocation.get_project_identifier()}"
        )

        backend.add_user(allocation, user)


@shared_task(name="waldur_openportal.delete_user")
def delete_user(serialized_user):
    """
    Update the user by deleting them from all OpenPortal resources
    to which they have allocations. This is called when you want to
    completely delete the user.
    """
    logger.info(f"task.delete_user: {serialized_user}")
    user = core_utils.deserialize_instance(serialized_user)

    if not isinstance(user, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    for allocation in utils.get_project_allocations(user):
        if not allocation.has_project_identifier():
            logger.warning(
                f"OpenPortal - {allocation} has no project identifier, skipping"
            )
            continue

        backend = allocation.get_backend()

        if not allocation.is_added_to_openportal():
            allocation = backend.add_allocated_project(allocation)

        if allocation.is_added_to_openportal():
            print(
                f"Deleting user {user} from project {allocation.get_project_identifier()}"
            )
            backend.delete_user(allocation, user)


@shared_task(name="waldur_openportal.sync_allocation_usage")
def sync_allocation_usage(serialized_allocation):
    """
    This task is called to synchronise the usage for the passed allocation
    """
    logger.info(f"task.sync_allocation_usage: {serialized_allocation}")
    allocation = core_utils.deserialize_instance(serialized_allocation)

    openportal_backend: backend.OpenPortalBackend = allocation.get_backend()

    if not allocation.is_added_to_openportal():
        allocation = openportal_backend.add_allocated_project(allocation)

    if allocation.is_added_to_openportal():
        openportal_backend.sync_usage(allocation)


@shared_task(name="waldur_openportal.sync_allocation_users")
def sync_allocation_users(serialized_allocation):
    """
    This task is called to synchronise the allocations for all users
    associated with all allocations
    """
    logger.info(f"task.sync_allocation_users: {serialized_allocation}")
    allocation = core_utils.deserialize_instance(serialized_allocation)

    openportal_backend: backend.OpenPortalBackend = allocation.get_backend()

    if not allocation.is_added_to_openportal():
        allocation = openportal_backend.add_allocated_project(allocation)

    if allocation.is_added_to_openportal():
        openportal_backend.sync_users(allocation)


@shared_task(name="waldur_openportal.sync_usage")
def sync_usage():
    """
    This task is called to synchronise the usage for all allocations
    """
    logger.info("OpenPortal task.sync_usage")
    for allocation in models.Allocation.objects.filter(is_active=True):
        sync_allocation_usage.delay(core_utils.serialize_instance(allocation))


@shared_task(name="waldur_openportal.sync")
def sync():
    """
    This is a full OpenPortal sync - this will go through all projects
    and ensure that only users associated with those projects have
    the correct associations with any OpenPortal allocations.
    This will add and remove users as needed.
    """
    logger.info("OpenPortal task.sync")
    for customer in structure_models.Customer.objects.all():
        for allocation in get_structure_allocations(customer):
            sync_allocation_users.delay(core_utils.serialize_instance(allocation))


@shared_task(name="waldur_openportal.sync_project")
def sync_project(serialized_project):
    """
    This is a project sync - this will go through all users associated
    with the project and ensure that they have the correct associations
    with any OpenPortal allocations. This will add and remove users as needed.
    """
    logger.info(f"OpenPortal task.sync_project: {serialized_project}")
    project = core_utils.deserialize_instance(serialized_project)

    for allocation in get_structure_allocations(project):
        sync_allocation_users.delay(core_utils.serialize_instance(allocation))
