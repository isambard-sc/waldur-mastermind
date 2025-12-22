import collections
import logging

from django.db.models import Q

from waldur_core.core.models import User
from waldur_core.structure import models as structure_models
from waldur_mastermind.marketplace.enums import ResourceStates
from waldur_mastermind.marketplace.models import Offering, Resource

logger = logging.getLogger(__name__)


def get_proposal_team_members(round_obj, proposal_states=None):
    """
    Get all unique users who are team members of proposals in a round.

    Args:
        round_obj: Round object to filter proposals by
        proposal_states: Optional list of proposal states to filter by

    Returns:
        Set of User objects
    """
    try:
        from waldur_mastermind.proposal.models import Proposal
        from waldur_core.permissions.utils import get_permissions
    except ImportError:
        logger.warning("Proposal app not installed, skipping proposal team members")
        return set()

    # Get proposals in the round
    proposals = Proposal.objects.filter(round=round_obj)

    # Filter by proposal states if provided
    if proposal_states:
        proposals = proposals.filter(state__in=proposal_states)

    # Collect all unique users from all proposals
    users = set()
    for proposal in proposals:
        # Get all active permissions (team members) for this proposal
        permissions = get_permissions(proposal)
        for perm in permissions:
            if perm.user.is_active and perm.user.email:
                users.add(perm.user)

    return users


def get_user_emails_for_query(query):
    """Get email addresses for users matching the query, including notification emails."""
    users, _, _, notification_emails = get_mapping(query)
    result = []

    for user in users.values():
        if user.email:
            result.append(user.email)

    if notification_emails:
        for email in notification_emails.keys():
            result.append(email)

    return result


def get_mapping(query):
    users = {}
    user_offerings = collections.defaultdict(set)
    user_customers = collections.defaultdict(set)
    notification_emails = {}

    all_users = query.get("all_users")
    if all_users:
        users = {
            user.id: user
            for user in User.objects.filter(is_active=True).exclude(email="")
        }
        # Include notification emails for all customers targeting
        all_customers = structure_models.Customer.objects.exclude(
            notification_emails__isnull=True
        ).exclude(notification_emails="")
        for customer in all_customers:
            notification_emails.update(get_customer_notification_emails_dict(customer))
    else:
        customers = query.get("customers", [])
        offerings = query.get("offerings", [])
        round_obj = query.get("round")
        proposal_states = query.get("proposal_states")

        # Handle proposal round filtering
        if round_obj:
            proposal_users = get_proposal_team_members(round_obj, proposal_states)
            for user in proposal_users:
                users[user.id] = user

        if offerings:
            resources = Resource.objects.filter(
                Q(offering__in=offerings) | Q(offering__parent__in=offerings)
            ).exclude(state=ResourceStates.TERMINATED)

            # Drop resources from non-whitelisted customers
            if customers:
                resources = resources.filter(
                    project__customer_id__in=[customer.id for customer in customers]
                )

            # Use only unique customers
            resource_customer_ids = (
                resources.values_list("project__customer_id", flat=True)
                .distinct()
                .order_by()
            )

            filtered_customers = structure_models.Customer.objects.filter(
                id__in=resource_customer_ids
            )
            for customer in filtered_customers:
                customer_offering_ids = set(
                    resources.filter(project__customer=customer)
                    .values_list("offering", flat=True)
                    .distinct()
                    .order_by()
                )
                customer_offerings = Offering.objects.filter(
                    id__in=customer_offering_ids
                )
                for user in customer.get_users():
                    users[user.id] = user
                    user_offerings[user.id] = user_offerings[user.id] | set(
                        customer_offerings
                    )
                    user_customers[user.id].add(customer)

                notification_emails.update(
                    get_customer_notification_emails_dict(customer, customer_offerings)
                )

        for customer in customers:
            for user in customer.get_users():
                users[user.id] = user
                user_customers[user.id].add(customer)
            for email, info in get_customer_notification_emails_dict(customer).items():
                if email not in notification_emails:
                    notification_emails[email] = info

    # Handle additional_recipients
    additional_recipients = query.get("additional_recipients", [])
    # additional_recipients is now a list of email addresses
    for email in additional_recipients:
        # Find users with this email and add them
        matching_users = User.objects.filter(email=email, is_active=True)
        for user in matching_users:
            users[user.id] = user

    # Handle send_to_me
    send_to_me = query.get("send_to_me", False)
    request = query.get("_request")  # We'll need to pass this from the view
    if send_to_me and request and hasattr(request, "user"):
        current_user = request.user
        if current_user.is_active and current_user.email:
            users[current_user.id] = current_user

    # Handle excluded_recipients - remove them from the final list
    excluded_recipients = query.get("excluded_recipients", [])
    # excluded_recipients is now a list of email addresses
    for email in excluded_recipients:
        # Find and remove users with this email
        users_to_remove = [
            user_id for user_id, user in users.items() if user.email == email
        ]
        for user_id in users_to_remove:
            users.pop(user_id, None)
        # Also remove from notification_emails if present
        if email in notification_emails:
            del notification_emails[email]

    return users, user_offerings, user_customers, notification_emails


def get_recipients_for_query(query):
    users, user_offerings, user_customers, notification_emails = get_mapping(query)

    result = []
    for user_id, user in users.items():
        result.append(
            {
                "full_name": user.full_name,
                "email": user.email,
                "offerings": [
                    {"uuid": offering.uuid, "name": offering.name}
                    for offering in user_offerings[user_id]
                ],
                "customers": [
                    {"uuid": customer.uuid, "name": customer.name}
                    for customer in user_customers[user_id]
                ],
            }
        )

    for _, contact_info in notification_emails.items():
        result.append(
            {
                "full_name": f"Notification email for {contact_info['customer'].name}",
                "email": contact_info["email"],
                "offerings": [
                    {"uuid": offering.uuid, "name": offering.name}
                    for offering in contact_info["offerings"]
                ],
                "customers": [
                    {
                        "uuid": contact_info["customer"].uuid,
                        "name": contact_info["customer"].name,
                    }
                ],
            }
        )

    return sorted(result, key=lambda row: row["full_name"])


def get_customer_notification_emails(customer):
    if (
        not customer
        or not hasattr(customer, "notification_emails")
        or not customer.notification_emails
    ):
        return []

    try:
        emails = []
        notification_emails_str = str(customer.notification_emails).strip()
        for email_str in notification_emails_str.split(","):
            email = email_str.strip()
            if email:
                emails.append(email)
        return emails

    except (TypeError, ValueError) as e:
        logger.warning(
            f"Failed to parse notification emails for customer {getattr(customer, 'uuid', 'unknown')}: {e}"
        )
        return []


def get_customer_notification_emails_dict(customer, offerings=None):
    notification_emails = {}
    for email in get_customer_notification_emails(customer):
        notification_emails[email] = {
            "email": email,
            "customer": customer,
            "offerings": offerings or set(),
        }
    return notification_emails
