import logging
import datetime

from celery import shared_task

from waldur_core.core import utils as core_utils
from waldur_core.core.models import User
from waldur_core.structure import models as structure_models
from waldur_mastermind.invoices import models as invoice_models

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
    now = datetime.datetime.now()
    fail_count = 0

    for allocation in models.Allocation.objects.filter(is_active=True):
        try:
            sync_allocation_usage(allocation)
        except Exception as e:
            logger.error(f"Failed to sync usage for {allocation}: {e}")
            fail_count += 1

            if fail_count > 5 and (datetime.datetime.now() - now).seconds > 60:
                logger.error("Too many failures - aborting")
                return
            elif (datetime.datetime.now() - now).seconds > 120:
                logger.error("Took too long - aborting")
                return

    # Now update any limits that will be changed by the above usage
    logger.info("OpenPortal task.sync_usage [limits]")

    for project_credit in invoice_models.ProjectCredit.objects.all():
        project = project_credit.project

        if project.is_expired:
            continue

        credits_available = project_credit.value

        if credits_available is None or credits_available <= 0:
            credits_available = 0
        else:
            credits_available = float(credits_available)

        # find any openportal allocations associated with the project
        allocations = models.Allocation.objects.filter(project=project, is_active=True)

        if not allocations:
            logger.warning(
                f"Project {project} has no OpenPortal allocations - skipping"
            )
            continue

        # Calculate the total usage so far this month across OpenPortal allocations
        # for this project - if it exceeds the number of project credits available
        # then we have to set the limits to zero to prevent any more spend
        if credits_available > 0:
            total_spend = 0.0

            for allocation in allocations:
                total_spend += float(allocation.node_usage)

            logger.info(
                f"Total spend for {project} is {total_spend} hours - {credits_available} available"
            )

            if total_spend >= credits_available:
                logger.warning(
                    f"Total spend for {project} exceeds available credits - setting limits to zero"
                )
                credits_available = 0

        for allocation in allocations:
            try:
                if not allocation.is_added_to_openportal():
                    logger.warning(
                        f"Allocation {allocation} not in OpenPortal - skipping"
                    )
                    continue

                if allocation.node_limit is None or allocation.node_limit <= 0:
                    node_limit = 0
                else:
                    node_limit = float(allocation.node_limit)

                backend = allocation.get_backend()

                if abs(node_limit - credits_available) > 0.001:
                    logger.info(
                        f"Setting node limit for {allocation} to {credits_available} hours"
                    )

                    allocation.node_limit = credits_available
                    backend.set_resource_limits(allocation)
                    allocation.save()
                else:
                    # double check that the limit is set correctly
                    current_limit = backend.get_resource_limits(
                        allocation.get_project_identifier()
                    )

                    if (
                        current_limit is None
                        or abs(current_limit.hours - allocation.node_limit) > 0.001
                    ):
                        logger.warning(
                            f"Node limit for {allocation} is not set correctly - changing from {current_limit} to {allocation.node_limit}"
                        )
                        backend.set_resource_limits(allocation)

            except Exception as e:
                logger.error(f"Failed to sync limits for {allocation}: {e}")
                fail_count += 1

                if fail_count > 5 and (datetime.datetime.now() - now).seconds > 60:
                    logger.error("Too many failures - aborting")
                    return
                elif (datetime.datetime.now() - now).seconds > 120:
                    logger.error("Took too long - aborting")
                    return


@shared_task(name="waldur_openportal.sync")
def sync():
    """
    This is a full OpenPortal sync - this will go through all projects
    and ensure that only users associated with those projects have
    the correct associations with any OpenPortal allocations.
    This will add and remove users as needed.
    """
    logger.info("OpenPortal task.sync")

    now = datetime.datetime.now()
    fail_count = 0

    # First, sync all of the usage, so we have up-to-date accounting data
    for customer in structure_models.Customer.objects.all():
        for allocation in get_structure_allocations(customer):
            try:
                sync_allocation_users(allocation)
            except Exception as e:
                logger.error(f"Failed to sync users for {allocation}: {e}")
                fail_count += 1

                if fail_count > 5 and (datetime.datetime.now() - now).seconds > 60:
                    logger.error("Too many failures - aborting")
                    break
                elif (datetime.datetime.now() - now).seconds > 120:
                    logger.error("Took too long - aborting")
                    break


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

    now = datetime.datetime.now()
    fail_count = 0

    for allocation in get_structure_allocations(project):
        try:
            sync_allocation_users(allocation)
        except Exception as e:
            logger.error(f"Failed to sync users for {allocation}: {e}")
            fail_count += 1

            if fail_count > 5 and (datetime.datetime.now() - now).seconds > 60:
                logger.error("Too many failures - aborting")
                break
            elif (datetime.datetime.now() - now).seconds > 120:
                logger.error("Took too long - aborting")
                break
