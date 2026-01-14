import re
import decimal
import logging

from constance import config

from django.utils import timezone

from waldur_core.core import utils as core_utils
from waldur_core.core import models as core_models
from waldur_core.structure import models as structure_models

from waldur_core.structure.managers import (
    get_connected_customers,
    get_connected_projects,
    get_project_users,
)

from waldur_core.permissions.utils import get_permissions
from waldur_core.users.enums import InvitationState
from waldur_core.users import models as user_models
from waldur_core.users import tasks as user_tasks

from waldur_mastermind.invoices import models as invoice_models

from . import models, utils


logger = logging.getLogger(__name__)

MAPPING = {
    "node_usage": "op_node_usage",
}

FIELD_NAMES = MAPPING.keys()

QUOTA_NAMES = MAPPING.values()


def get_openportal_robot():
    """
    Return the OpenPortal robot user.
    This is used for system-level operations that require a user context.
    """
    from waldur_core.core import models

    robot_user, created = models.User.objects.get_or_create(
        username="openportal_robot",
        defaults={
            "is_staff": True,
            "is_active": True,
            "description": (
                "Special user used for performing actions on behalf of OpenPortal."
            ),
            "first_name": "OpenPortal",
            "last_name": "Robot",
            "email": config.SITE_EMAIL,
        },
    )
    if created:
        robot_user.set_unusable_password()
        robot_user.save(update_fields=["password"])
    return robot_user


def format_current_month():
    today = timezone.now()
    month_start = core_utils.month_start(today).strftime("%Y-%m-%d")
    month_end = core_utils.month_end(today).strftime("%Y-%m-%d")
    return month_start, month_end


def sanitize_allocation_name(name):
    incorrect_symbols_regex = r"[^%s]+" % models.OPENPORTAL_ALLOCATION_REGEX
    return re.sub(incorrect_symbols_regex, "", name)


def get_customer_allocations(user):
    """
    Return the allocations to the user associated with being a customer.
    This will typically be all of the allocations associated with customer
    roles in, e.g. an organisation
    """
    connected_customers = get_connected_customers(user)

    customer_allocations = models.Allocation.objects.filter(
        is_active=True, project__customer__in=connected_customers
    )

    return customer_allocations


def get_project_allocations(user):
    """
    Return all of the allocations associated with the passed user
    to any project. This gives the projects in which the user is active.
    Projects in which the user is inactive are ignored
    """
    connected_projects = get_connected_projects(user)

    project_allocations = models.Allocation.objects.filter(
        is_active=True, project__in=connected_projects
    )

    return project_allocations


def get_remote_project_allocations(user):
    """
    Return all of the remote allocations associated with the passed user
    to any project. This gives the projects in which the user is active.
    Projects in which the user is inactive are ignored
    """
    connected_projects = get_connected_projects(user)

    project_allocations = models.RemoteAllocation.objects.filter(
        is_active=True, project__in=connected_projects
    )

    return project_allocations


def set_default_project_shortname(project):
    """
    Set and return the default shortname for the passed project.
    If the project already has a shortname, the original
    shortname will be returned
    """
    # Use the project slug as the default shortname
    if project.slug is None:
        logger.error(f"Project slug is None for project: {project}")
        raise ValueError(f"Project slug is None for project: {project}")

    shortname = str(project.slug).strip()

    if len(shortname) == 0:
        logger.error(f"Project slug is empty for project: {project}")
        raise ValueError(f"Project slug is empty for project: {project}")

    if len(shortname) > models.MAX_PROJECT_SHORTNAME_LENGTH:
        logger.warning(
            f"Project slug '{shortname}' is longer than {models.MAX_PROJECT_SHORTNAME_LENGTH} characters for project: {project}"
        )
        shortname = shortname[: models.MAX_PROJECT_SHORTNAME_LENGTH]

    project_info, created = models.ProjectInfo.objects.get_or_create(
        project=project, shortname=shortname
    )

    if created:
        project_info.sanitise()
    else:
        logger.warning(
            f"ProjectInfo already exists for project {project} with shortname {project_info.shortname}"
        )

    if project_info.shortname is None:
        logger.error(f"Empty shortname for project: {project}")
        raise ValueError(f"Empty shortname for project: {project}")

    return project_info.shortname


def get_project_shortname(project):
    """
    Return the preferred shortname for the passed project.
    """
    # look up the short name from the models.ProjectInfo object
    # associated with this project
    project_info, created = models.ProjectInfo.objects.get_or_create(project=project)

    project_info.sanitise()

    if project_info.shortname is None:
        logger.error(f"Empty shortname for project: {project}")

    return project_info.shortname


def get_user_shortname(user):
    """
    Return the preferred shortname for the passed user.
    """
    # look up the short name from the models.UserInfo object
    # associated with this user
    user_info, created = models.UserInfo.objects.get_or_create(user=user)

    user = user_info.user

    # if this is not set, then copy it in from the user.unix_username
    # property (which may disappear in the future)
    if user_info.shortname is None and hasattr(user, "unix_username"):
        if user.unix_username is not None:
            logger.debug(f"Copying shortname from the user's unix_username for {user}")
            user_info.set_shortname(user.unix_username)
            user_info.save()

    if user_info.shortname is None:
        logger.error(f"Empty shortname for user: {user}")

    return user_info.shortname


def get_first_day_of_month(date):
    """
    Return the first day of the month for the given date.
    """
    return date.replace(day=1)


def get_last_day_of_month(date):
    """
    Return the last day of the month for the given date.
    """
    next_month = date.replace(day=28) + timezone.timedelta(days=4)
    return next_month - timezone.timedelta(days=next_month.day)


def get_association(user, allocation):
    """
    Return the association between the user and the allocation.
    """
    if not isinstance(allocation, models.Allocation):
        raise TypeError("allocation must be an instance of models.Allocation")

    if not isinstance(user, core_models.User):
        raise TypeError("user must be an instance of core_models.User")

    try:
        return models.Association.objects.get(user=user, allocation=allocation)
    except models.Association.MultipleObjectsReturned:
        logger.warning(
            f"Multiple associations found for {user} and {allocation} - removing all but the first one"
        )
        associations = models.Association.objects.filter(
            user=user, allocation=allocation
        )

        if associations.exists():
            first_association = associations.first()

            if first_association is None:
                logger.error(f"No associations found for {user} and {allocation}?")
                raise models.Association.DoesNotExist(
                    f"No association found for {user} and {allocation}"
                )

            if len(associations) > 1:
                for association in associations[1:]:
                    logger.info(
                        f"Deleting duplicate association {association} for {user} and {allocation}"
                    )
                    association.delete()

            return first_association
        else:
            logger.error(
                f"No associations found for {user} and {allocation} after deletion"
            )
            raise models.Association.DoesNotExist(
                f"No association found for {user} and {allocation}"
            )


def get_remote_association(user, allocation):
    """
    Return the association between the user and the allocation.
    """
    if not isinstance(allocation, models.RemoteAllocation):
        raise TypeError("allocation must be an instance of models.RemoteAllocation")

    if not isinstance(user, core_models.User):
        raise TypeError("user must be an instance of core_models.User")

    try:
        return models.RemoteAssociation.objects.get(user=user, allocation=allocation)
    except models.RemoteAssociation.MultipleObjectsReturned:
        logger.warning(
            f"Multiple associations found for {user} and {allocation} - removing all but the first one"
        )
        associations = models.RemoteAssociation.objects.filter(
            user=user, allocation=allocation
        )

        if associations.exists():
            first_association = associations.first()

            if first_association is None:
                logger.error(f"No associations found for {user} and {allocation}?")
                raise models.RemoteAssociation.DoesNotExist(
                    f"No association found for {user} and {allocation}"
                )

            if len(associations) > 1:
                for association in associations[1:]:
                    logger.info(
                        f"Deleting duplicate association {association} for {user} and {allocation}"
                    )
                    association.delete()

            return first_association
        else:
            logger.error(
                f"No associations found for {user} and {allocation} after deletion"
            )
            raise models.RemoteAssociation.DoesNotExist(
                f"No association found for {user} and {allocation}"
            )


def fix_total_allocation(project):
    """
    Run this function to fix the balance of managed projects so that
    their balance at the beginning of the month is correct. This fixes
    any issues or discrepancies that may have arisen.
    """
    try:
        managed_project = models.ManagedProject.objects.get(project=project)
    except models.ManagedProject.DoesNotExist:
        logger.error(f"Project {project} is not a managed project")
        return

    project_template = managed_project.get_project_template()

    if project_template is None:
        logger.error(f"Managed project {project} has no project template")
        return

    details = managed_project.get_details()

    if details is None:
        logger.error(f"Managed project {project} has no details")
        return

    allocation = project_template.convert_to_credits(details.allocation)

    set_project_credits(project, allocation)


def get_project_spend_info(
    project, include_current_month: bool = True
) -> tuple[decimal.Decimal, decimal.Decimal]:
    """
    Return a tuple of the total credits and total spend for the passed project

    Args:
        project: The project to get spend info for
        include_current_month: If False, exclude current month's invoice items from spend calculation
    """
    if not isinstance(project, structure_models.Project):
        raise TypeError("project must be an instance of Project")

    total_credits = decimal.Decimal(0.0)
    total_spend = decimal.Decimal(0.0)

    # Get all the allocations for the project
    try:
        project_credit = invoice_models.ProjectCredit.objects.get(project=project)
        total_credits = project_credit.value if project_credit else decimal.Decimal(0.0)
    except invoice_models.ProjectCredit.DoesNotExist:
        total_credits = decimal.Decimal(0.0)

    # Get all the spend for the project
    try:
        invoice_items = invoice_models.InvoiceItem.objects.filter(project=project)

        # Exclude current month if requested
        if not include_current_month:
            now = timezone.now()
            current_year = now.year
            current_month = now.month

            invoice_items = invoice_items.exclude(
                invoice__year=current_year, invoice__month=current_month
            )
    except Exception as e:
        logger.error(f"Failed to get invoice items for project {project}: {e}")
        invoice_items = []

    for invoice_item in invoice_items:
        usage = decimal.Decimal(invoice_item.price)

        if usage < 0:
            # this is a credit, so add it to the total credits
            total_credits += abs(usage)
        elif usage > 0:
            # this is a charge, so add it to the total spend
            total_spend += usage

        # no need to do anything if usage == 0

    logger.info(
        f"Project {project} has total credits: {total_credits}, total spend: {total_spend} "
        f"(include_current_month={include_current_month})"
    )

    return (total_credits, total_spend)


def get_project_credits(project) -> decimal.Decimal:
    """
    Get the total lifetime credits awarded to the project.
    If the project has no credits, return 0.0
    """
    if not isinstance(project, structure_models.Project):
        raise TypeError("project must be an instance of Project")

    (total_credits, total_spend) = get_project_spend_info(
        project, include_current_month=False
    )

    return total_credits + total_spend


def set_project_credits(project, credits: decimal.Decimal | float):
    """
    Set the credits for the project to the passed value
    """
    if not isinstance(project, structure_models.Project):
        raise TypeError("project must be an instance of Project")

    try:
        credits = decimal.Decimal(credits)
    except (ValueError, TypeError):
        logger.error(f"Invalid credits value: {credits} for project {project}")
        raise ValueError(f"Invalid credits value: {credits} for project {project}")

    if project.is_expired or project.is_removed:
        logger.warning(
            f"Cannot set credits for project {project} as it is expired or removed"
        )
        raise ValueError(
            f"Cannot set credits for project {project} as it is expired or removed"
        )

    if credits < decimal.Decimal(0.0):
        credits = decimal.Decimal(0.0)

    # Get spend info excluding current month (we want start-of-month balance)
    (total_credits, total_spend) = get_project_spend_info(
        project, include_current_month=False
    )

    # Calculate what the credit balance should be: allocation - historical_spend
    # This gives us the start-of-month balance for the current month
    desired_credit_balance = credits - total_spend

    if desired_credit_balance < decimal.Decimal(0):
        logger.warning(
            f"Desired credit balance ({desired_credit_balance}) is negative for project {project}. "
            f"Allocation: {credits}, Spend: {total_spend}. "
            f"Setting balance to 0."
        )
        desired_credit_balance = decimal.Decimal(0)

    change_in_credits = desired_credit_balance - total_credits

    if abs(change_in_credits) < decimal.Decimal(0.01):
        # no change in credits, so nothing to do
        logger.info(
            f"No change in credits for project {project}: {total_credits} -> {desired_credit_balance} "
            f"(allocation: {credits}, spend: {total_spend})"
        )
        return

    if change_in_credits > decimal.Decimal(0):
        # Increasing credits -
        # Get the CustomerCredit and make sure that it has enough credits itself...
        customer_credit, created = invoice_models.CustomerCredit.objects.get_or_create(
            customer=project.customer,
        )

        remaining_customer_credit = (
            customer_credit.value - customer_credit.allocated_to_projects
        )

        # We need a little more than the change just for safety
        needed_customer_credit = change_in_credits + decimal.Decimal(0.1)

        if remaining_customer_credit < needed_customer_credit:
            logger.warning(
                f"Not enough customer credit to allocate {change_in_credits} to project {project}. "
                f"Remaining customer credit is {remaining_customer_credit} while "
                f"we need {needed_customer_credit}."
            )

            customer_credit.value = (
                customer_credit.value
                + needed_customer_credit
                - remaining_customer_credit
            )
            customer_credit.save(update_fields=["value"])
            logger.warning(
                f"Customer credit for {project.customer} increased to {customer_credit.value}"
            )

    # Now set the credits
    project_credit, created = invoice_models.ProjectCredit.objects.get_or_create(
        project=project,
    )

    try:
        project_credit.value = desired_credit_balance
        project_credit.save(update_fields=["value"])
        logger.info(
            f"Project credits for project {project} set to {project_credit.value} (was {total_credits}, "
            f"allocation: {credits}, spend: {total_spend}, change: {change_in_credits})"
        )
    except Exception as e:
        logger.error(
            f"Failed to set project credits for project {project} to {credits + change_in_credits}: {e}"
        )
        raise


def get_project_members(project) -> dict[str, str]:
    """
    Return a dictionary of all of the current members of the project,
    (email addresses) and their current roles.
    """
    if not isinstance(project, structure_models.Project):
        raise TypeError("project must be an instance of Project")

    members = {}

    project_user_ids = get_project_users(project.id)

    users = core_models.User.objects.filter(id__in=project_user_ids)

    for user in users:
        if not user.is_active:
            continue

        if user.email is None:
            continue

        email = str(user.email).strip().lower()

        if len(email) == 0:
            continue

        try:
            permission = get_permissions(project, user).first()
        except Exception:
            continue

        if permission is None:
            continue

        if permission.role is None:
            continue

        if permission.role.name is None:
            continue

        members[email] = str(permission.role.name)

    invitations = user_models.Invitation.objects.filter(
        state=InvitationState.PENDING,
    )

    for invite in invitations:
        if invite.scope != project:
            continue

        if invite.email is None:
            continue

        email = str(invite.email).strip().lower()

        if len(email) == 0:
            continue

        if invite.role is None:
            continue

        if invite.role.name is None:
            continue

        if email in members:
            # already a member, so skip
            continue

        members[email] = str(invite.role.name)

    logger.info(f"Current members of project {project}: {members}")

    return members


def invite_user_to_project(project, email, role, send_email: bool = True):
    """
    Invite a user to the project with the specified email and role.
    If the user already exists, update their role in the project.
    If send_email is True, send an invitation email.
    """
    if not isinstance(project, structure_models.Project):
        raise TypeError("project must be an instance of Project")

    if not isinstance(email, str) or not email:
        raise ValueError("email must be a non-empty string")

    logger.info(
        f"Inviting user with email {email} to project {project} with role {role} - NEEDS IMPLEMENTING"
    )

    invitation = user_models.Invitation.objects.create(
        scope=project,
        email=email,
        role=role,
        created_by=utils.get_openportal_robot(),
        state=InvitationState.PENDING,
        customer=project.customer,
    )

    if project.start_date and project.start_date > timezone.now().date():
        invitation.state = InvitationState.PENDING_PROJECT

    logger.info(
        f"Created invitation {invitation} for user {email} to project {project} with role {role}"
    )

    invitation.save()

    if send_email:
        user_tasks.process_invitation.delay(invitation.uuid.hex, "OpenPortal")


def sync_openportal_shortnames_to_slugs():
    """
    Synchronize shortnames from ProjectInfo and UserInfo to their respective
    Project and User slug fields. This is used in "Project Management" mode
    where these shortnames are used instead of proposal IDs.

    This function:
    1. Copies ProjectInfo.shortname to Project.slug where they differ
    2. Copies UserInfo.shortname to User.slug where they differ

    Only updates slugs where:
    - The shortname exists (is not None/empty)
    - The shortname differs from the current slug

    Returns:
        dict: Statistics about the sync operation with keys:
            - projects_updated: Number of projects updated
            - users_updated: Number of users updated
            - projects_skipped: Number of projects skipped (no shortname or already matching)
            - users_skipped: Number of users skipped (no shortname or already matching)
            - errors: List of error messages encountered
    """
    projects_updated = 0
    users_updated = 0
    projects_skipped = 0
    users_skipped = 0
    errors = []

    logger.info("Starting sync of OpenPortal shortnames to slugs...")

    # Sync ProjectInfo shortnames to Project slugs
    for project_info in models.ProjectInfo.objects.all().select_related("project"):
        try:
            # Skip if no shortname or project doesn't exist
            if not project_info.shortname or not project_info.project:
                projects_skipped += 1
                logger.debug(
                    f"Skipping ProjectInfo {project_info.id}: "
                    f"shortname={project_info.shortname}, project exists={bool(project_info.project)}"
                )
                continue

            project = project_info.project
            shortname = project_info.shortname.strip()

            # Skip if slug already matches
            if project.slug == shortname:
                projects_skipped += 1
                logger.debug(
                    f"Skipping project {project.name} ({project.uuid}): "
                    f"slug already matches shortname '{shortname}'"
                )
                continue

            # Update the slug
            old_slug = project.slug
            project.slug = shortname
            project.save(update_fields=["slug"])
            projects_updated += 1

            logger.info(
                f"Updated project {project.name} ({project.uuid}) slug: "
                f"'{old_slug}' -> '{shortname}'"
            )

        except Exception as e:
            error_msg = (
                f"Failed to sync ProjectInfo {project_info.id} "
                f"(shortname='{project_info.shortname}'): {e}"
            )
            errors.append(error_msg)
            logger.error(error_msg, exc_info=True)

    # Sync UserInfo shortnames to User slugs
    for user_info in models.UserInfo.objects.all().select_related("user"):
        try:
            # Skip if no shortname or user doesn't exist
            if not user_info.shortname or not user_info.user:
                users_skipped += 1
                logger.debug(
                    f"Skipping UserInfo {user_info.id}: "
                    f"shortname={user_info.shortname}, user exists={bool(user_info.user)}"
                )
                continue

            user = user_info.user
            shortname = user_info.shortname.strip()

            # Skip if slug already matches
            if user.slug == shortname:
                users_skipped += 1
                logger.debug(
                    f"Skipping user {user.username} ({user.uuid}): "
                    f"slug already matches shortname '{shortname}'"
                )
                continue

            # Update the slug
            old_slug = user.slug
            user.slug = shortname
            user.save(update_fields=["slug"])
            users_updated += 1

            logger.info(
                f"Updated user {user.username} ({user.uuid}) slug: "
                f"'{old_slug}' -> '{shortname}'"
            )

        except Exception as e:
            error_msg = (
                f"Failed to sync UserInfo {user_info.id} "
                f"(shortname='{user_info.shortname}'): {e}"
            )
            errors.append(error_msg)
            logger.error(error_msg, exc_info=True)

    # Log summary
    logger.info(
        f"Sync complete. Projects: {projects_updated} updated, {projects_skipped} skipped. "
        f"Users: {users_updated} updated, {users_skipped} skipped. "
        f"Errors: {len(errors)}"
    )

    return {
        "projects_updated": projects_updated,
        "users_updated": users_updated,
        "projects_skipped": projects_skipped,
        "users_skipped": users_skipped,
        "errors": errors,
    }
