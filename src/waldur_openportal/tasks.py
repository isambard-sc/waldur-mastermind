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

    if isinstance(serialized_allocation, models.Allocation):
        allocation = serialized_allocation
    else:
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

    if isinstance(serialized_user, User):
        user = serialized_user
    else:
        user = core_utils.deserialize_instance(serialized_user)

    if not isinstance(user, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    for allocation in utils.get_project_allocations(user):
        try:
            # adding and updating are the same thing in OpenPortal
            backend = allocation.get_backend()

            # This call will make sure to create the project if it
            # failed creation before
            allocation = backend.check_added_allocation(allocation)

            logger.info(f"Adding user {user} to {allocation}")

            backend.add_user(allocation, user)
        except Exception as e:
            logger.error(f"Failed to add {user} to {allocation}: {e}")


@shared_task(name="waldur_openportal.delete_user")
def delete_user(serialized_user):
    """
    Update the user by deleting them from all OpenPortal resources
    to which they have allocations. This is called when you want to
    completely delete the user.
    """
    logger.info(f"task.delete_user: {serialized_user}")

    if isinstance(serialized_user, User):
        user = serialized_user
    else:
        user = core_utils.deserialize_instance(serialized_user)

    if not isinstance(user, User):
        logger.error(f"OpenPortal - {user} is not a User instance - it is {type(user)}")
        return

    for allocation in utils.get_project_allocations(user):
        try:
            if not allocation.is_added_to_openportal():
                logger.warning(f"{allocation} not in OpenPortal - skipping")
                continue

            backend = allocation.get_backend()
            allocation = backend.check_added_allocation(allocation)

            logger.info(f"Deleting user {user} from project {allocation}")

            backend.delete_user(allocation, user)
        except Exception as e:
            logger.error(f"Failed to delete {user} from {allocation}: {e}")


@shared_task(name="waldur_openportal.sync_allocation_usage")
def sync_allocation_usage(serialized_allocation):
    """
    This task is called to synchronise the usage for the passed allocation
    """
    logger.info(f"task.sync_allocation_usage: {serialized_allocation}")

    if isinstance(serialized_allocation, models.Allocation):
        allocation = serialized_allocation
    else:
        allocation = core_utils.deserialize_instance(serialized_allocation)

    backend = allocation.get_backend()

    allocation = backend.check_added_allocation(allocation)
    backend.sync_usage(allocation)


@shared_task(name="waldur_openportal.sync_allocation_users")
def sync_allocation_users(serialized_allocation):
    """
    This task is called to synchronise the allocations for all users
    associated with all allocations
    """
    logger.info(f"task.sync_allocation_users: {serialized_allocation}")

    if isinstance(serialized_allocation, models.Allocation):
        allocation = serialized_allocation
    else:
        allocation = core_utils.deserialize_instance(serialized_allocation)

    backend = allocation.get_backend()

    allocation = backend.check_added_allocation(allocation)

    backend.sync_users(allocation)


@shared_task(name="waldur_openportal.sync_usage")
def sync_usage():
    """
    This task is called to synchronise the usage for all allocations
    """
    logger.info("OpenPortal task.sync_usage")
    for allocation in models.Allocation.objects.filter(is_active=True):
        try:
            sync_allocation_usage(allocation)
        except Exception as e:
            logger.error(f"Failed to sync usage for {allocation}: {e}")


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
            try:
                sync_allocation_users(allocation)
            except Exception as e:
                logger.error(f"Failed to sync users for {allocation}: {e}")


@shared_task(name="waldur_openportal.sync_project")
def sync_project(serialized_project):
    """
    This is a project sync - this will go through all users associated
    with the project and ensure that they have the correct associations
    with any OpenPortal allocations. This will add and remove users as needed.
    """
    logger.info(f"OpenPortal task.sync_project: {serialized_project}")

    if isinstance(serialized_project, structure_models.Project):
        project = serialized_project
    else:
        project = core_utils.deserialize_instance(serialized_project)

    for allocation in get_structure_allocations(project):
        try:
            sync_allocation_users(allocation)
        except Exception as e:
            logger.error(f"Failed to sync users for {allocation}: {e}")
