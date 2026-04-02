import calendar
import datetime
import json
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

    set_project_credits(project, allocation, silent=True)


def get_project_spend_info(
    project,
    include_current_month: bool = True,
    silent: bool = False,
) -> tuple[decimal.Decimal, decimal.Decimal]:
    """
    Return a tuple of the total credits and total spend for the passed project

    Args:
        project: The project to get spend info for
        include_current_month: If False, exclude current month's invoice items from spend calculation
        silent: If True, suppress logging
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

    if not silent:
        logger.info(
            f"Project {project} has total credits: {total_credits}, total spend: {total_spend} "
            f"(include_current_month={include_current_month})"
        )

    return (total_credits, total_spend)


def get_project_credits(project, silent: bool = False) -> decimal.Decimal:
    """
    Get the total lifetime credits awarded to the project.
    If the project has no credits, return 0.0
    """
    if not isinstance(project, structure_models.Project):
        raise TypeError("project must be an instance of Project")

    (total_credits, total_spend) = get_project_spend_info(
        project, include_current_month=False, silent=silent
    )

    return total_credits + total_spend


def set_project_credits(
    project, credits: decimal.Decimal | float, silent: bool = False
):
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
        project, include_current_month=False, silent=silent
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
        if not silent:
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
        if not silent:
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


def _user_info_dict(user):
    return {
        "uuid": str(user.uuid),
        "full_name": user.full_name,
        "username": user.username,
        "email": user.email,
    }


def _resolve_useridentifier_from_slugs(identifier: str):
    """
    Fallback resolver when the Association record has been deleted.

    A UserIdentifier has the form "{user_slug}.{project_slug}.{portal}".
    We verify the portal suffix matches, then look up the project and user
    by their slugs and confirm the user is still a member of that project.
    Returns a user info dict or None.
    """
    from waldur_core.permissions.models import UserRole
    from waldur_core.structure import models as structure_models

    from . import op as openportal

    try:
        portal = str(openportal.get_portal())
    except Exception:
        return None

    portal_suffix = f".{portal}"
    if not identifier.endswith(portal_suffix):
        return None

    remainder = identifier[: -len(portal_suffix)]

    # remainder is "{user_slug}.{project_slug}" — split from the right once
    parts = remainder.rsplit(".", 1)
    if len(parts) != 2:
        return None

    user_slug, project_slug = parts

    try:
        project = structure_models.Project.objects.get(slug=project_slug)
    except structure_models.Project.DoesNotExist:
        return None

    try:
        user = structure_models.User.objects.get(slug=user_slug)
    except structure_models.User.DoesNotExist:
        return None

    if not UserRole.objects.filter(user=user, scope=project, is_active=True).exists():
        return None

    return _user_info_dict(user)


def resolve_emails(emails: list) -> dict:
    """
    Map email address strings to Waldur user info dicts.

    Used for cached reports from remote portals, where the user_mapping field
    contains email addresses rather than UserIdentifier strings.

    Returns dict of {email_string: {"uuid", "email", "full_name", "username"}}
    Emails that do not match any Waldur user map to None.
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()
    users = {u.email: u for u in User.objects.filter(email__in=emails)}
    return {
        email: (_user_info_dict(users[email]) if email in users else None)
        for email in emails
    }


def resolve_useridentifiers(identifiers: list) -> dict:
    """
    Map OpenPortal UserIdentifier strings to Waldur user info dicts.

    Primary chain: Association.useridentifier == identifier -> Association.user
    Fallback (when Association is deleted): parse the identifier as
    "{user_slug}.{project_slug}.{portal}" and verify the user is still a
    member of the project.

    Returns dict of {identifier_string: {"uuid", "email", "full_name", "username"}}
    Missing or unmapped identifiers map to None.
    """
    result = {}
    for identifier in identifiers:
        association = (
            models.Association.objects.filter(useridentifier=identifier)
            .select_related("user")
            .first()
        )

        if association is not None and association.user is not None:
            result[identifier] = _user_info_dict(association.user)
            continue

        # Association missing or user deleted — try slug-based fallback
        result[identifier] = _resolve_useridentifier_from_slugs(identifier)

    return result


def backfill_usage_report_cache():
    """
    Backfill CachedProjectUsageReport for all historical months.

    Run this once manually after deploying to populate the cache for months
    prior to the current one. The regular sync_usage task handles the current
    (and previous) month going forward, so this only fetches up to and
    including the month before the current one.

    Covers all allocations that ever had an OpenPortal project identifier,
    including those on inactive or soft-deleted projects, so the full
    historical record is preserved.

    A project's history starts at its start_date (falling back to its
    created date if start_date is not set), and ends at the earlier of:
      - the month before the current month, or
      - the month it expired / passed its grace period end date.

    Skips any month for which a complete CachedProjectUsageReport already
    exists, so it is safe to re-run.
    """
    from . import op as openportal
    from .backend import OpenPortalBackend

    today = timezone.now().date()
    # Last day of the previous month — we backfill up to and including this
    first_of_current = today.replace(day=1)
    last_historical = first_of_current - datetime.timedelta(days=1)

    all_allocations = list(models.Allocation.objects.all().select_related("project"))

    total_fetched = 0
    total_skipped = 0
    total_errors = 0

    for allocation in all_allocations:
        project = allocation.project

        if not allocation.has_project_identifier():
            logger.debug(f"backfill: skipping {allocation} - no project identifier")
            continue

        # Determine the start month for this allocation
        start_date = project.start_date or project.created.date()
        start_month_first = start_date.replace(day=1)

        # Determine the end month (don't go past last_historical)
        if project.end_date_with_grace:
            project_end = min(project.end_date_with_grace, last_historical)
        else:
            project_end = last_historical

        if start_month_first > project_end:
            logger.debug(
                f"backfill: skipping {allocation} - no historical months to fill"
            )
            continue

        try:
            backend = OpenPortalBackend(allocation.service_settings)
        except Exception as e:
            logger.error(f"backfill: could not create backend for {allocation}: {e}")
            total_errors += 1
            continue

        resource = str(backend.client.destination())
        project_identifier = str(allocation.get_project_identifier())

        # Walk month by month from start_month_first to the end month
        cursor = start_month_first
        while cursor <= project_end:
            year, month = cursor.year, cursor.month
            last_day = calendar.monthrange(year, month)[1]
            month_end = cursor.replace(day=last_day)

            logger.info(
                f"backfill: processing {project_identifier} {year}-{month:02d} ({resource})"
            )

            # Skip if we already have a complete cached report for this month
            already_complete = models.CachedProjectUsageReport.objects.filter(
                year=year,
                month=month,
                project_identifier=project_identifier,
                resource=resource,
                is_complete=True,
            ).exists()

            if already_complete:
                logger.debug(
                    f"backfill: skipping {project_identifier} {year}-{month:02d} "
                    f"({resource}) - already complete"
                )
                total_skipped += 1
            else:
                try:
                    date_range = openportal.DateRange(cursor, month_end)

                    # should try to get the report 10 times, as sometimes this
                    # can take OpenPortal a while if there are lots of jobs that month
                    report = None

                    for attempt in range(10):
                        try:
                            report = backend.client.get_usage_report(
                                allocation.get_project_identifier(), date_range
                            )
                            break
                        except Exception as e:
                            logger.warning(
                                f"backfill: attempt {attempt + 1} - failed to fetch report for "
                                f"{project_identifier} {year}-{month:02d} ({resource}): {e}"
                            )

                    if report is None:
                        logger.error(
                            f"backfill: failed to fetch report for {project_identifier} "
                            f"{year}-{month:02d} ({resource}) after 10 attempts"
                        )
                        total_errors += 1
                        continue

                    models.CachedProjectUsageReport.objects.update_or_create(
                        year=year,
                        month=month,
                        project_identifier=project_identifier,
                        resource=resource,
                        defaults={
                            "is_complete": True,
                            "report": json.loads(report.to_json()),
                        },
                    )
                    logger.info(
                        f"backfill: cached {project_identifier} {year}-{month:02d} ({resource})"
                    )
                    total_fetched += 1
                except Exception as e:
                    logger.error(
                        f"backfill: failed for {project_identifier} {year}-{month:02d}: {e}"
                    )
                    total_errors += 1

            # Advance to the first of the next month
            if month == 12:
                cursor = cursor.replace(year=year + 1, month=1, day=1)
            else:
                cursor = cursor.replace(month=month + 1, day=1)

    logger.info(
        f"backfill_usage_report_cache complete: "
        f"{total_fetched} fetched, {total_skipped} skipped, {total_errors} errors"
    )
    return {
        "fetched": total_fetched,
        "skipped": total_skipped,
        "errors": total_errors,
    }


def compare_historical_usage_with_cache():
    """
    Compare historical monthly node-hour consumption recorded in HistoricalAllocation
    against the totals from CachedProjectUsageReport for the same months.

    This is useful for understanding the impact of changes to node-hour accounting
    (e.g. rounding up to the next highest node second) on previously recorded usage.

    Only complete months are compared (is_complete=True on both sides). Months
    where no CachedProjectUsageReport exists are skipped.

    Returns a dict keyed by project_identifier with:
        - allocation_name: human-readable name of the allocation
        - total_historical: sum of HistoricalAllocation.node_usage across all complete months
        - total_cached: sum of CachedProjectUsageReport total_usage.hours across the same months
        - total_difference: total_cached - total_historical (positive = cached is higher)
        - months: list of per-month dicts with keys:
            year, month, historical, cached, difference
    """
    results = {}

    historical_qs = (
        models.HistoricalAllocation.objects.filter(is_complete=True)
        .select_related("allocation")
        .order_by("allocation__id", "year", "month")
    )

    for hist in historical_qs:
        allocation = hist.allocation
        if not allocation.has_project_identifier():
            continue

        project_identifier = str(allocation.get_project_identifier())

        cached_reports = models.CachedProjectUsageReport.objects.filter(
            year=hist.year,
            month=hist.month,
            project_identifier=project_identifier,
            is_complete=True,
        )

        if not cached_reports.exists():
            continue

        try:
            cached_total = sum(
                float(cr.get_report().total_usage.hours) for cr in cached_reports
            )
        except Exception as e:
            logger.warning(
                f"compare_historical_usage_with_cache: could not read cached report "
                f"for {project_identifier} {hist.year}-{hist.month:02d}: {e}"
            )
            continue

        historical = float(hist.node_usage)
        difference = cached_total - historical

        if project_identifier not in results:
            results[project_identifier] = {
                "allocation_name": allocation.name,
                "total_historical": 0.0,
                "total_cached": 0.0,
                "total_difference": 0.0,
                "months": [],
            }

        entry = results[project_identifier]
        entry["total_historical"] += historical
        entry["total_cached"] += cached_total
        entry["total_difference"] += difference
        entry["months"].append(
            {
                "year": hist.year,
                "month": hist.month,
                "historical": historical,
                "cached": cached_total,
                "difference": difference,
            }
        )

    logger.info(
        f"compare_historical_usage_with_cache: compared {len(results)} projects"
    )
    return results


def backfill_remote_usage_report_cache():
    """
    Backfill CachedProjectUsageReport for all historical months using data
    fetched from remote portals via RemoteOpenPortalBackend.

    This is the remote-portal equivalent of backfill_usage_report_cache(): it
    iterates over RemoteAllocation objects and fetches usage reports from the
    remote portal for each historical month, storing them in the local
    CachedProjectUsageReport table.

    Run this once manually after deploying to populate the cache for months
    prior to the current one. The regular sync_remote_usage task handles the
    current (and previous) month going forward.

    Skips any month for which a complete CachedProjectUsageReport already
    exists, so it is safe to re-run.
    """
    from . import op as openportal
    from .remotebackend import RemoteOpenPortalBackend

    today = timezone.now().date()
    first_of_current = today.replace(day=1)
    last_historical = first_of_current - datetime.timedelta(days=1)

    all_allocations = list(
        models.RemoteAllocation.objects.all().select_related("project")
    )

    total_fetched = 0
    total_skipped = 0
    total_errors = 0

    for allocation in all_allocations:
        project = allocation.project

        if not allocation.has_project_identifier():
            logger.debug(
                f"backfill_remote: skipping {allocation} - no project identifier"
            )
            continue

        start_date = project.start_date or project.created.date()
        start_month_first = start_date.replace(day=1)

        if project.end_date_with_grace:
            project_end = min(project.end_date_with_grace, last_historical)
        else:
            project_end = last_historical

        if start_month_first > project_end:
            logger.debug(
                f"backfill_remote: skipping {allocation} - no historical months to fill"
            )
            continue

        try:
            backend = RemoteOpenPortalBackend(allocation.service_settings)
        except Exception as e:
            logger.error(
                f"backfill_remote: could not create backend for {allocation}: {e}"
            )
            total_errors += 1
            continue

        resource = str(backend.client.destination())
        project_identifier = str(allocation.get_project_identifier())

        cursor = start_month_first
        while cursor <= project_end:
            year, month = cursor.year, cursor.month
            last_day = calendar.monthrange(year, month)[1]
            month_end = cursor.replace(day=last_day)

            logger.info(
                f"backfill_remote: processing {project_identifier} "
                f"{year}-{month:02d} ({resource})"
            )

            already_complete = models.CachedProjectUsageReport.objects.filter(
                year=year,
                month=month,
                project_identifier=project_identifier,
                resource=resource,
                is_complete=True,
            ).exists()

            if already_complete:
                logger.debug(
                    f"backfill_remote: skipping {project_identifier} "
                    f"{year}-{month:02d} ({resource}) - already complete"
                )
                total_skipped += 1
            else:
                try:
                    date_range = openportal.DateRange(cursor, month_end)

                    report = None
                    for attempt in range(10):
                        try:
                            report = backend.client.get_usage_report(
                                allocation.get_project_identifier(), date_range
                            )
                            break
                        except Exception as e:
                            logger.warning(
                                f"backfill_remote: attempt {attempt + 1} - failed to fetch "
                                f"report for {project_identifier} {year}-{month:02d}: {e}"
                            )

                    if report is None:
                        logger.error(
                            f"backfill_remote: failed to fetch report for "
                            f"{project_identifier} {year}-{month:02d} after 10 attempts"
                        )
                        total_errors += 1
                    else:
                        models.CachedProjectUsageReport.objects.update_or_create(
                            year=year,
                            month=month,
                            project_identifier=project_identifier,
                            resource=resource,
                            defaults={
                                "is_complete": True,
                                "report": json.loads(report.to_json()),
                            },
                        )
                        logger.info(
                            f"backfill_remote: cached {project_identifier} "
                            f"{year}-{month:02d} ({resource})"
                        )
                        total_fetched += 1
                except Exception as e:
                    logger.error(
                        f"backfill_remote: failed for {project_identifier} "
                        f"{year}-{month:02d}: {e}"
                    )
                    total_errors += 1

            if month == 12:
                cursor = cursor.replace(year=year + 1, month=1, day=1)
            else:
                cursor = cursor.replace(month=month + 1, day=1)

    logger.info(
        f"backfill_remote_usage_report_cache complete: "
        f"{total_fetched} fetched, {total_skipped} skipped, {total_errors} errors"
    )
    return {
        "fetched": total_fetched,
        "skipped": total_skipped,
        "errors": total_errors,
    }


def compare_historical_remote_usage_with_cache():
    """
    Compare historical monthly node-hour consumption recorded in HistoricalRemoteAllocation
    against the totals from CachedProjectUsageReport for the same months.

    This is the remote-portal equivalent of compare_historical_usage_with_cache: it
    uses HistoricalRemoteAllocation (populated by RemoteOpenPortalBackend.sync_usage)
    and the CachedProjectUsageReport records that sync_usage now also writes.

    Only complete months are compared (is_complete=True on both sides). Months
    where no CachedProjectUsageReport exists are skipped.

    Returns a dict keyed by project_identifier with:
        - allocation_name: human-readable name of the remote allocation
        - total_historical: sum of HistoricalRemoteAllocation.node_usage across all complete months
        - total_cached: sum of CachedProjectUsageReport total_usage.hours across the same months
        - total_difference: total_cached - total_historical (positive = cached is higher)
        - months: list of per-month dicts with keys:
            year, month, historical, cached, difference
    """
    results = {}

    historical_qs = (
        models.HistoricalRemoteAllocation.objects.filter(is_complete=True)
        .select_related("allocation")
        .order_by("allocation__id", "year", "month")
    )

    for hist in historical_qs:
        allocation = hist.allocation
        if not allocation.has_project_identifier():
            continue

        project_identifier = str(allocation.get_project_identifier())

        cached_reports = models.CachedProjectUsageReport.objects.filter(
            year=hist.year,
            month=hist.month,
            project_identifier=project_identifier,
            is_complete=True,
        )

        if not cached_reports.exists():
            continue

        try:
            cached_total = sum(
                float(cr.get_report().total_usage.hours) for cr in cached_reports
            )
        except Exception as e:
            logger.warning(
                f"compare_historical_remote_usage_with_cache: could not read cached report "
                f"for {project_identifier} {hist.year}-{hist.month:02d}: {e}"
            )
            continue

        historical = float(hist.node_usage)
        difference = cached_total - historical

        if project_identifier not in results:
            results[project_identifier] = {
                "allocation_name": allocation.name,
                "total_historical": 0.0,
                "total_cached": 0.0,
                "total_difference": 0.0,
                "months": [],
            }

        entry = results[project_identifier]
        entry["total_historical"] += historical
        entry["total_cached"] += cached_total
        entry["total_difference"] += difference
        entry["months"].append(
            {
                "year": hist.year,
                "month": hist.month,
                "historical": historical,
                "cached": cached_total,
                "difference": difference,
            }
        )

    logger.info(
        f"compare_historical_remote_usage_with_cache: compared {len(results)} projects"
    )
    return results


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


PERSONAL_EMAIL_DOMAINS = frozenset(
    [
        # Google
        "gmail.com",
        "googlemail.com",
        # Yahoo
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.fr",
        "yahoo.de",
        "yahoo.es",
        "yahoo.it",
        "yahoo.com.au",
        "yahoo.ca",
        "yahoo.co.in",
        "ymail.com",
        # Microsoft
        "hotmail.com",
        "hotmail.co.uk",
        "hotmail.fr",
        "hotmail.de",
        "hotmail.es",
        "hotmail.it",
        "outlook.com",
        "outlook.co.uk",
        "outlook.fr",
        "live.com",
        "live.co.uk",
        "live.fr",
        "msn.com",
        # Apple
        "icloud.com",
        "me.com",
        "mac.com",
        # Proton
        "protonmail.com",
        "protonmail.ch",
        "proton.me",
        "pm.me",
        # AOL
        "aol.com",
        "aol.co.uk",
        # Other common
        "mail.com",
        "zoho.com",
        "yandex.com",
        "yandex.ru",
        "gmx.com",
        "gmx.de",
        "gmx.net",
        "web.de",
        "t-online.de",
        "tutanota.com",
        "tutanota.de",
        "fastmail.com",
        "fastmail.fm",
        "inbox.com",
        "hushmail.com",
        "mailfence.com",
        "disroot.org",
        "riseup.net",
        "posteo.de",
        "posteo.net",
        "mailbox.org",
        "cock.li",
        "seznam.cz",
        "wp.pl",
        "o2.pl",
        "interia.pl",
    ]
)


def is_likely_personal_email_address(email_or_domain: str) -> bool:
    """
    Return True if the email address or domain is a known personal /
    consumer email provider.

    Accepts either a full address ("user@gmail.com") or just the
    domain ("gmail.com").  The check is case-insensitive.

    Not exhaustive — only checks against a curated list of well-known
    personal email providers.
    """
    if "@" in email_or_domain:
        domain = email_or_domain.split("@")[-1].strip().lower()
    else:
        domain = email_or_domain.strip().lower()
    return domain in PERSONAL_EMAIL_DOMAINS


def get_project_member_domains(project) -> list:
    """
    Return a sorted list of unique email domains used by the active
    members of *project*, excluding domains that are likely personal
    email providers (gmail.com, hotmail.com, etc.).

    Returns an empty list if the project has no members with
    institutional email addresses.
    """
    domains = set()
    try:
        for user in project.get_users():
            if user.email:
                domain = user.email.split("@")[-1].strip().lower()
                if domain and not is_likely_personal_email_address(domain):
                    domains.add(domain)
    except Exception as e:
        logger.warning(f"get_project_member_domains: failed for {project}: {e}")
    return sorted(domains)


def get_proposal_links_for_project(project):
    """
    Return ``(link_award, link_call)`` dicts for the first Proposal
    attached to *project*, or ``(None, None)`` if no proposal is found.

    ``link_award`` points to the proposal page in homeport:
        url  = call-management/{customer_uuid}/proposals/{proposal_uuid}/
        id   = proposal name

    ``link_call`` points to the call page in homeport:
        url  = call/{call_uuid}/
        id   = "{call.name} - {round.start_time:%Y-%m}"
    """
    try:
        from waldur_core.core.utils import format_homeport_link
        from waldur_mastermind.proposal.models import Proposal

        proposal = (
            Proposal.objects.filter(project=project)
            .select_related("round__call__manager__customer")
            .first()
        )
        if proposal is None:
            return None, None

        call = proposal.round.call
        customer_uuid = call.manager.customer.uuid

        link_award = {
            "id": proposal.name,
            "url": format_homeport_link(
                "call-management/{customer_uuid}/proposals/{proposal_uuid}/",
                customer_uuid=customer_uuid,
                proposal_uuid=proposal.uuid,
            ),
        }

        round_label = proposal.round.start_time.strftime("%Y-%m")
        link_call = {
            "id": f"{call.name} - {round_label}",
            "url": format_homeport_link(
                "call/{call_uuid}/",
                call_uuid=call.uuid,
            ),
        }

        return link_award, link_call

    except Exception as e:
        logger.warning(f"get_proposal_links_for_project: failed for {project}: {e}")
        return None, None


def backfill_remote_projects(dry_run: bool = False):
    """
    Create or update RemoteProject objects for all existing
    RemoteAllocations that have a project identifier set.

    This is a one-time utility for migrating existing data.  Safe to
    run multiple times — get_or_create ensures no duplicates.

    Args:
        dry_run: If True, no database writes are performed.  The return
                 value shows exactly what *would* happen, including a
                 'plan' list of per-allocation actions.

    Returns a summary dict with counts, errors, and (in dry-run mode)
    a 'plan' list of dicts describing what would be done.
    """
    from . import remote_project_service  # noqa: F401 (used when not dry)

    created_count = 0
    updated_count = 0
    skipped_count = 0
    errors = []
    plan = []  # populated in dry-run mode

    allocations = models.RemoteAllocation.objects.filter(is_active=True)

    for allocation in allocations:
        try:
            backend = allocation.get_backend()
            destination = str(backend.destination())
        except Exception as e:
            msg = (
                f"backfill_remote_projects: cannot get destination"
                f" for {allocation}: {e}"
            )
            errors.append(msg)
            logger.warning(msg)
            if dry_run:
                plan.append(
                    {
                        "allocation": str(allocation),
                        "action": "error",
                        "reason": msg,
                    }
                )
            continue

        identifier = None
        try:
            identifier = (
                str(allocation.get_remote_project_identifier())
                if allocation.has_remote_project_identifier()
                else None
            )

            if identifier is not None:
                existing = models.RemoteProject.objects.filter(
                    destination=destination,
                    identifier=identifier,
                ).first()
            else:
                existing = models.RemoteProject.objects.filter(
                    destination=destination,
                    identifier__isnull=True,
                    current_project=allocation.project,
                ).first()

            if dry_run:
                alloc_value, _ = allocation._get_requested_allocation()
                plan.append(
                    {
                        "allocation": str(allocation),
                        "identifier": identifier,
                        "destination": destination,
                        "action": "update" if existing else "create",
                        "is_added": allocation.is_added,
                        "allocation_value": (
                            float(alloc_value) if alloc_value is not None else None
                        ),
                        "current_project": (
                            str(allocation.project) if allocation.project else None
                        ),
                    }
                )
                if existing is None:
                    created_count += 1
                else:
                    updated_count += 1
                continue

            remote_project = remote_project_service.get_or_create_remote_project(
                allocation,
                destination,
                remote_identifier=identifier,
            )
            remote_project_service.ensure_current_attachment(remote_project)

            if existing is None:
                # Newly created — set state and allocation from what
                # we know about the allocation right now.  Do NOT set
                # last_contact_time: we don't know when we last heard
                # from the remote portal for this historical entry.
                if allocation.is_added:
                    remote_project.state = models.RemoteProjectState.ACTIVE
                    alloc_value, _ = allocation._get_requested_allocation()
                    if alloc_value is not None:
                        remote_project.current_allocation = decimal.Decimal(
                            str(alloc_value)
                        )
                    remote_project.save()

                models.RemoteProjectAuditEntry.objects.create(
                    remote_project=remote_project,
                    event_type=(models.RemoteProjectAuditEventType.AWARD_CREATED),
                    note=("Created by backfill_remote_projects utility."),
                )
                created_count += 1
                logger.info(
                    f"backfill_remote_projects: created RemoteProject"
                    f" {identifier} via {destination}"
                )
            else:
                updated_count += 1
                logger.debug(
                    f"backfill_remote_projects: updated RemoteProject"
                    f" {identifier} via {destination}"
                )

        except Exception as e:
            msg = (
                f"backfill_remote_projects: failed for {allocation}"
                f" ({identifier} via {destination}): {e}"
            )
            errors.append(msg)
            logger.error(msg, exc_info=True)

    prefix = "[DRY RUN] " if dry_run else ""
    logger.info(
        f"{prefix}backfill_remote_projects complete: "
        f"{created_count} created, {updated_count} updated, "
        f"{skipped_count} skipped, {len(errors)} errors"
    )

    result = {
        "dry_run": dry_run,
        "created": created_count,
        "updated": updated_count,
        "skipped": skipped_count,
        "errors": errors,
    }
    if dry_run:
        result["plan"] = plan
    return result
