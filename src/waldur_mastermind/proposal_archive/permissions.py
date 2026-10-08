"""Who may read the archive.

The archive is read-only but not public: proposals carry
``project_is_confidential``, and reviews carry reviewer identities and candid
private comments.  See ``docs/guides/awards-site-upgrade-plan.md`` §4.2.

One deliberate narrowing against the old app: reviewer identity and review text
are never shown to applicants here, whatever the original call's
``reviewer_identity_visible_to_submitters`` / ``reviews_visible_to_submitters``
said.  The archive is a record for administrators, not a continuation of the
review process, and the cost of being wrong is asymmetric.
"""

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q

from waldur_core.permissions import utils as permission_utils
from waldur_core.structure import models as structure_models


def is_administrator(user):
    return user.is_authenticated and (user.is_staff or user.is_support)


def visible_customer_uuids(user):
    """UUIDs of the customers the user holds any active role on."""
    if not user.is_authenticated:
        return []
    customer_ct = ContentType.objects.get_for_model(structure_models.Customer)
    ids = permission_utils.get_scope_ids(user, customer_ct)
    return list(
        structure_models.Customer.objects.filter(id__in=ids).values_list(
            "uuid", flat=True
        )
    )


def filter_calls(queryset, user):
    """Calls run by an organisation the user belongs to."""
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    return queryset.filter(customer_uuid__in=visible_customer_uuids(user))


def filter_proposals(queryset, user):
    """The above, plus the proposals the user wrote."""
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    return queryset.filter(
        Q(call__customer_uuid__in=visible_customer_uuids(user))
        | Q(created_by_uuid=user.uuid)
    )


def filter_rounds(queryset, user):
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    return queryset.filter(call__customer_uuid__in=visible_customer_uuids(user))


def filter_reviews_scope(queryset, user):
    """Narrow a queryset of *proposals* to the review audience.

    Reviews and call-manager notes are visible to a narrower set of people than
    the proposal they belong to: the applicant can read their own proposal but
    must not read what was said about it. Both endpoints share this so the two
    cannot drift apart -- the filter is on ``call__customer_uuid``, so it works
    for any model that reaches a call that way.
    """
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    return queryset.filter(call__customer_uuid__in=visible_customer_uuids(user))


def filter_reviews(queryset, user):
    """Administrators and call managers only -- never the applicant."""
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    return queryset.filter(
        proposal__call__customer_uuid__in=visible_customer_uuids(user)
    )


def filter_memberships(queryset, user):
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    customer_uuids = visible_customer_uuids(user)
    return queryset.filter(
        Q(call__customer_uuid__in=customer_uuids)
        | Q(organisation_customer_uuid__in=customer_uuids)
    )


def filter_call_documents(queryset, user):
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    return queryset.filter(call__customer_uuid__in=visible_customer_uuids(user))


def filter_proposal_documents(queryset, user):
    if not user.is_authenticated:
        return queryset.none()
    if is_administrator(user):
        return queryset
    return queryset.filter(
        Q(proposal__call__customer_uuid__in=visible_customer_uuids(user))
        | Q(proposal__created_by_uuid=user.uuid)
    )
