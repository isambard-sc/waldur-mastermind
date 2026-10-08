"""Read-only endpoints over the archive.

Access is by queryset filter rather than ``permission_factory``: there are no
actions to authorise, only rows to hide, and the rules in §4.2 are per-row --
a call manager sees their calls' proposals, an applicant sees their own.  Each
viewset narrows through the matching function in ``permissions.py``, which is
the same function ``media_access.py`` uses, so a document can never be
downloadable by someone who cannot see the record it hangs off.
"""

from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from waldur_core.core import views as core_views

from . import filters, models, permissions, serializers


class ArchivedCallViewSet(core_views.ReadOnlyActionsViewSet):
    queryset = models.ArchivedCall.objects.all()
    serializer_class = serializers.ArchivedCallSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = filters.ArchivedCallFilter
    lookup_field = "uuid"

    def get_queryset(self):
        queryset = permissions.filter_calls(super().get_queryset(), self.request.user)
        if self.action == "retrieve":
            return queryset.prefetch_related("rounds", "documents").annotate(
                proposal_count=Count("proposals", distinct=True)
            )
        return queryset

    def get_serializer_class(self):
        if self.action == "retrieve":
            return serializers.ArchivedCallDetailSerializer
        return super().get_serializer_class()


class ArchivedRoundViewSet(core_views.ReadOnlyActionsViewSet):
    queryset = models.ArchivedRound.objects.all().select_related("call")
    serializer_class = serializers.ArchivedRoundSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = filters.ArchivedRoundFilter
    lookup_field = "uuid"

    def get_queryset(self):
        return permissions.filter_rounds(super().get_queryset(), self.request.user)


class ArchivedProposalViewSet(core_views.ReadOnlyActionsViewSet):
    queryset = models.ArchivedProposal.objects.all().select_related("call", "round")
    serializer_class = serializers.ArchivedProposalSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = filters.ArchivedProposalFilter
    lookup_field = "uuid"

    def get_queryset(self):
        queryset = permissions.filter_proposals(
            super().get_queryset(), self.request.user
        )
        if self.action == "retrieve":
            return queryset.prefetch_related(
                "requested_resources", "documents", "memberships"
            )
        return queryset

    def get_serializer_class(self):
        if self.action == "retrieve":
            return serializers.ArchivedProposalDetailSerializer
        if self.action == "notes":
            return serializers.ArchivedProposalNotesSerializer
        return super().get_serializer_class()

    @extend_schema(
        summary="Call-manager notes on an archived proposal",
        responses={200: serializers.ArchivedProposalNotesSerializer},
        description=(
            "Notes were only ever visible to call managers and staff, so they "
            "are behind the same check as reviews rather than on the proposal "
            "itself, which its author can read."
        ),
    )
    @action(detail=True, methods=["get"])
    def notes(self, request, uuid=None):
        # get_object() would apply the proposal filter, which is wider than
        # this endpoint wants: the author passes it and must not see the notes.
        queryset = permissions.filter_reviews_scope(
            models.ArchivedProposal.objects.all(), request.user
        )
        proposal = queryset.filter(uuid=uuid).first()
        if proposal is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(self.get_serializer(proposal).data)


class ArchivedReviewViewSet(core_views.ReadOnlyActionsViewSet):
    """Administrators and call managers only -- never the applicant.

    The old call's ``reviews_visible_to_submitters`` flag is deliberately not
    consulted: the archive is a record for administrators, not a continuation
    of the review process, and the cost of being wrong is asymmetric.
    """

    queryset = models.ArchivedReview.objects.all().select_related("proposal")
    serializer_class = serializers.ArchivedReviewSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = filters.ArchivedReviewFilter
    lookup_field = "uuid"

    def get_queryset(self):
        return permissions.filter_reviews(super().get_queryset(), self.request.user)


class ArchivedMembershipViewSet(core_views.ReadOnlyActionsViewSet):
    """Who held which role on an archived call or proposal.

    Worth an endpoint of its own rather than only a nested field: the question
    people actually ask of it is "what did this person have access to?", which
    is a query across proposals, not within one.
    """

    queryset = models.ArchivedMembership.objects.all().select_related(
        "call", "proposal"
    )
    serializer_class = serializers.ArchivedMembershipSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = filters.ArchivedMembershipFilter
    lookup_field = "uuid"

    def get_queryset(self):
        return permissions.filter_memberships(super().get_queryset(), self.request.user)


class ArchiveResolveViewSet(core_views.ReadOnlyActionsViewSet):
    """Resolve an original UUID to whatever the archive now holds for it.

    Archive rows keep the UUIDs the fork's rows had, which is what lets an old
    ``/proposals/<uuid>`` link keep working: the frontend tries the live
    proposal, gets a 404, and asks here. A 404 from this endpoint means the
    UUID is genuinely unknown -- or belongs to something the caller may not
    see, which is the same answer as far as the caller is concerned.
    """

    queryset = models.ArchivedProposal.objects.none()
    serializer_class = serializers.ArchiveResolveSerializer
    lookup_field = "uuid"
    disabled_actions = ["create", "update", "partial_update", "destroy", "list"]

    @extend_schema(
        summary="Resolve an archived UUID",
        responses={200: serializers.ArchiveResolveSerializer},
    )
    def retrieve(self, request, uuid=None):
        user = request.user
        candidates = (
            (
                "proposal",
                permissions.filter_proposals(
                    models.ArchivedProposal.objects.all(), user
                ),
            ),
            ("call", permissions.filter_calls(models.ArchivedCall.objects.all(), user)),
            (
                "round",
                permissions.filter_rounds(models.ArchivedRound.objects.all(), user),
            ),
        )
        for kind, queryset in candidates:
            match = queryset.filter(uuid=uuid).first()
            if match is None:
                continue
            name = getattr(match, "name", None) or str(match)
            serializer = self.get_serializer(
                {"kind": kind, "uuid": match.uuid, "name": name}
            )
            return Response(serializer.data)
        return Response(status=status.HTTP_404_NOT_FOUND)
