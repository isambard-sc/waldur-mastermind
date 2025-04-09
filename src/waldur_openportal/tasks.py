import logging
import datetime
import time

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


@shared_task(name="waldur_openportal.send_notifications")
def send_notifications():
    """
    This task is called to send notifications to all users associated
    with any OpenPortal allocations.
    """
    logger.info("OpenPortal task.send_notifications")

    # make sure that we only run during "office hours"
    # (10am to 3pm) - this is a bit of a hack, but it will do for now
    now = datetime.datetime.now()

    if now.hour < 10 or now.hour > 15:
        logger.debug("Not sending notifications - outside office hours")
        return

    # Get today's date
    today = datetime.date.today()

    num_emails_sent = 0

    # Loop over all ProjectCredit objects - no need to send notifications
    # to projects that don't have any credits allocated
    for project_credit in invoice_models.ProjectCredit.objects.all():
        if num_emails_sent > 500:
            logger.warning("Sent over 500 emails already - stopping")
            return

        project = project_credit.project

        if project.is_expired:
            continue

        # get the end date for this project
        end_date = project.end_date

        # check that the project is not expired (sometimes expired hasn't worked?)
        if end_date is not None and end_date < today:
            # project is expired - no need to send notifications
            continue

        # Check to see if this project should be notified
        notification, created = models.ProjectNotification.objects.get_or_create(
            project=project
        )

        if notification.frequency == 0:
            # No notifications - skip
            continue

        should_notify = False

        if created or notification.last_notification is None:
            should_notify = True
        elif (
            notification.last_notification
            + datetime.timedelta(days=notification.frequency)
            <= today
        ):
            should_notify = True

        if not should_notify:
            continue

        # Check to see if this project has any credits available
        credits_available = float(project_credit.value)

        if credits_available is None or credits_available <= 0:
            credits_available = 0
        else:
            credits_available = float(credits_available)

        # find any openportal allocations associated with the project
        allocations = models.Allocation.objects.filter(project=project, is_active=True)

        # Calculate the total usage so far this month across OpenPortal allocations
        total_spend = 0.0

        for allocation in allocations:
            total_spend += float(allocation.node_usage)

        notification_subject = _notification_subject(project, today)

        notification_body = _notification_body(
            project,
            today,
            credits_available,
            total_spend,
            end_date,
            notification.frequency,
        )

        # Send the notification to each user - wait 50ms between each
        # notification to avoid overwhelming the mail server
        for user in project.get_users():
            try:
                logger.info(f"Sending notification to {user} in {project}")
                logger.debug(f"Notification subject: {notification_subject}")
                logger.debug(f"Notification body: {notification_body}")

                core_utils.send_mail(
                    subject=notification_subject,
                    body=notification_body,
                    to=[user.email],
                )
                num_emails_sent += 1
                time.sleep(0.05)
            except Exception as e:
                logger.error(f"Failed to send notification to {user.email}: {e}")

        # Update the last notification date
        notification.last_notification = today
        notification.save()


def _notification_subject(project, today):
    """
    This function returns the subject for the notification email
    for the passed project generated on the passed date
    """
    return f"Isambard Project Status Update - {today.strftime('%d %B %Y')}"


def _notification_body(
    project, today, credits_available, total_spend, end_date, update_frequency
):
    """
    This function returns the body for the notification email
    for the passed project generated on the passed date. This
    communicates the number of credits available, the total spend
    on the project, and when the project will end.
    """

    remaining = credits_available - total_spend
    if remaining < 0:
        remaining = 0

    if end_date is None:
        date_info = ""
    else:
        date = end_date.strftime("%d %B %Y")

        days_remaining = (end_date - today).days

        if days_remaining < 0:
            days_remaining = "today"
        elif days_remaining == 1:
            days_remaining = "tomorrow"
        else:
            days_remaining = f"in {days_remaining} days time"

        date_info = f"""

All node hours must be consumed before the {date}, which is {days_remaining}.

You must copy back all data before this date. You won't be able to login after your project ends and all remaining data will be deleted."""

    if update_frequency < 1:
        update_frequency = 1

    if update_frequency == 1:
        update_frequency = "day"
    elif update_frequency == 7:
        update_frequency = "week"
    elif update_frequency == 14:
        update_frequency = "fortnight"
    else:
        update_frequency = f"{update_frequency} days"

    # This would eventually be better templated ;-)
    body = f"""
Here is your regular update for your Isambard project “{project.name}”

To date, {total_spend:.2f} node hours have been used, leaving {remaining:.2f} remaining to consume before the end of your project.{date_info}

For more detail, view your project at https://portal.isambard.ac.uk.

To learn more about project accounting, read the documentation at https://docs.isambard.ac.uk/user-documentation/guides/accounting.

If you have any queries, please raise a ticket at https://support.isambard.ac.uk.

We will send you an update every {update_frequency}.

If you want to change the frequency of these updates please ask the project PI to raise a request at https://support.isambard.ac.uk.

"""

    return body
