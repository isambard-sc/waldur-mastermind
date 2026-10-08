"""Filters for the archive.

Everything filters on UUIDs and plain text rather than related objects: an
archive row's references are denormalised (§4.1), so there is nothing to join
to.  ``call_uuid`` on a proposal is the archived call's uuid, which is also the
*original* call's uuid, so links and bookmarks from the old site still work as
query parameters.
"""

import django_filters

from waldur_core.core import filters as core_filters

from . import models


class ArchivedCallFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_expr="icontains")
    state = django_filters.CharFilter()
    customer_uuid = core_filters.RelatedUUIDFilter(view_name="customer-detail")
    o = django_filters.OrderingFilter(fields=("created", "name", "state"))

    class Meta:
        model = models.ArchivedCall
        fields = []


class ArchivedRoundFilter(django_filters.FilterSet):
    call_uuid = core_filters.RelatedUUIDFilter(
        view_name="proposal-archive-call-detail", field_name="call__uuid"
    )
    o = django_filters.OrderingFilter(fields=("start_time", "cutoff_time", "created"))

    class Meta:
        model = models.ArchivedRound
        fields = []


class ArchivedProposalFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_expr="icontains")
    state = django_filters.CharFilter()
    call_uuid = core_filters.RelatedUUIDFilter(
        view_name="proposal-archive-call-detail", field_name="call__uuid"
    )
    round_uuid = core_filters.RelatedUUIDFilter(
        view_name="proposal-archive-round-detail", field_name="round__uuid"
    )
    project_uuid = core_filters.RelatedUUIDFilter(view_name="project-detail")
    created_by_uuid = core_filters.RelatedUUIDFilter(view_name="user-detail")
    created_by_username = django_filters.CharFilter(lookup_expr="icontains")
    submitted_after = django_filters.IsoDateTimeFilter(
        field_name="submitted_at", lookup_expr="gte"
    )
    submitted_before = django_filters.IsoDateTimeFilter(
        field_name="submitted_at", lookup_expr="lte"
    )
    o = django_filters.OrderingFilter(
        fields=("created", "submitted_at", "name", "state")
    )

    class Meta:
        model = models.ArchivedProposal
        fields = []


class ArchivedReviewFilter(django_filters.FilterSet):
    proposal_uuid = core_filters.RelatedUUIDFilter(
        view_name="proposal-archive-proposal-detail", field_name="proposal__uuid"
    )
    call_uuid = core_filters.RelatedUUIDFilter(
        view_name="proposal-archive-call-detail", field_name="proposal__call__uuid"
    )
    reviewer_uuid = core_filters.RelatedUUIDFilter(view_name="user-detail")
    state = django_filters.CharFilter()
    o = django_filters.OrderingFilter(fields=("created", "summary_score", "state"))

    class Meta:
        model = models.ArchivedReview
        fields = []


class ArchivedMembershipFilter(django_filters.FilterSet):
    scope_kind = django_filters.CharFilter()
    call_uuid = core_filters.RelatedUUIDFilter(
        view_name="proposal-archive-call-detail", field_name="call__uuid"
    )
    proposal_uuid = core_filters.RelatedUUIDFilter(
        view_name="proposal-archive-proposal-detail", field_name="proposal__uuid"
    )
    user_uuid = core_filters.RelatedUUIDFilter(view_name="user-detail")
    user_username = django_filters.CharFilter(lookup_expr="icontains")
    role_name = django_filters.CharFilter()
    is_active = django_filters.BooleanFilter()
    o = django_filters.OrderingFilter(fields=("created", "role_name", "user_username"))

    class Meta:
        model = models.ArchivedMembership
        fields = []
