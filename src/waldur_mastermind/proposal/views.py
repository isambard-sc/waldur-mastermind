import logging
from datetime import datetime, timedelta
from typing import cast

from django.db.models import OuterRef, ProtectedError, Q
from django.db.models.functions import Coalesce
from django.utils import timezone as timezone
from django.utils.translation import gettext_lazy as _
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import decorators, exceptions, response, status, viewsets
from rest_framework import permissions as rf_permissions

from waldur_core.checklist import models as checklist_models
from waldur_core.checklist import serializers as checklist_serializers
from waldur_core.checklist.mixins import ReviewerChecklistMixin, UserChecklistMixin
from waldur_core.core import validators as core_validators
from waldur_core.core.enums import ReviewStates
from waldur_core.core.exceptions import IncorrectStateException
from waldur_core.core.models import User
from waldur_core.core.utils import SubqueryCount
from waldur_core.core.views import (
    ActionMethodMixin,
    ActionsViewSet,
    ReadOnlyActionsViewSet,
)
from waldur_core.logging import event_logger
from waldur_core.logging.enums import EventType
from waldur_core.permissions import utils as permissions_utils
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CallRole, ProposalRole
from waldur_core.permissions.utils import has_permission, permission_factory
from waldur_core.permissions.views import UserRoleMixin
from waldur_core.structure import filters as structure_filters
from waldur_core.structure.managers import (
    filter_queryset_for_user,
    get_connected_customers,
)
from waldur_core.structure.permissions import _get_customer
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace.views import BaseMarketplaceView, PublicViewsetMixin
from waldur_mastermind.proposal import (
    filters,
    models,
    serializers,
    tasks,
    utils,
)
from waldur_mastermind.proposal import permissions as proposal_permissions
from waldur_mastermind.proposal.enums import (
    CallStates,
    ProposalStates,
    RequestedOfferingStates,
)
from waldur_core.media import models as media_models
from waldur_core.media import views as media_views

from .managers import get_connected_call_organizers, get_connected_calls
from .models import Proposal
from .serializers import ReviewSubmitSerializer

logger = logging.getLogger(__name__)


class CallManagingOrganisationViewSet(
    UserRoleMixin, PublicViewsetMixin, BaseMarketplaceView
):
    lookup_field = "uuid"
    queryset = models.CallManagingOrganisation.objects.all().order_by("customer__name")
    serializer_class = serializers.CallManagingOrganisationSerializer
    filterset_class = filters.CallManagingOrganisationFilter

    def destroy(self, request, *args, **kwargs):
        instance: models.CallManagingOrganisation = self.get_object()
        try:
            self.perform_destroy(instance)
            return response.Response(status=status.HTTP_204_NO_CONTENT)
        except ProtectedError:
            return response.Response(
                {
                    "detail": "Cannot delete this call manager as there are existing connected calls or user permissions."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    @extend_schema(
        description="Return statistics for call managing organisation.",
        request=None,
        responses=serializers.CallManagingOrganisationStatSerializer,
    )
    @decorators.action(detail=True)
    def stats(self, request, uuid=None):
        instance: models.CallManagingOrganisation = self.get_object()
        now = timezone.now()
        one_week_from_now = now + timedelta(weeks=1)

        open_calls = models.Call.objects.filter(
            state=CallStates.ACTIVE, manager=instance
        ).count()
        active_rounds = models.Round.objects.filter(
            cutoff_time__gte=now,
            call__manager=instance,
            call__state=CallStates.ACTIVE,
        ).count()
        accepted_proposals = models.Proposal.objects.filter(
            state=ProposalStates.ACCEPTED,
            round__call__manager=instance,
            round__call__state=CallStates.ACTIVE,
        ).count()
        pending_proposals = models.Proposal.objects.filter(
            state__in=[
                ProposalStates.IN_REVIEW,
                ProposalStates.SUBMITTED,
            ],
            round__call__manager=instance,
            round__call__state=CallStates.ACTIVE,
        ).count()
        pending_review = models.Review.objects.filter(
            state=models.Review.States.SUBMITTED,
            proposal__round__call__manager=instance,
            proposal__round__call__state=CallStates.ACTIVE,
        ).count()

        rounds_closing_in_one_week = models.Round.objects.filter(
            cutoff_time__gte=now,
            cutoff_time__lte=one_week_from_now,
            call__manager=instance,
            call__state=CallStates.ACTIVE,
        ).count()

        calls_closing_in_one_week = models.Call.objects.filter(
            state=CallStates.ACTIVE,
            round__cutoff_time__gte=now,
            round__cutoff_time__lte=one_week_from_now,
            manager=instance,
        ).count()

        offering_requests_pending = models.RequestedOffering.objects.filter(
            state=RequestedOfferingStates.REQUESTED,
            call__manager=instance,
            call__state=CallStates.ACTIVE,
        ).count()

        return response.Response(
            {
                "open_calls": open_calls,
                "active_rounds": active_rounds,
                "accepted_proposals": accepted_proposals,
                "pending_proposals": pending_proposals,
                "pending_review": pending_review,
                "rounds_closing_in_one_week": rounds_closing_in_one_week,
                "calls_closing_in_one_week": calls_closing_in_one_week,
                "offering_requests_pending": offering_requests_pending,
            },
            status=status.HTTP_200_OK,
        )


class PublicCallViewSet(viewsets.ReadOnlyModelViewSet):
    lookup_field = "uuid"
    queryset = models.Call.objects.filter(
        state__in=[CallStates.ACTIVE, CallStates.ARCHIVED]
    ).order_by("created")
    serializer_class = serializers.PublicCallSerializer
    filterset_class = filters.CallFilter
    permission_classes = (rf_permissions.AllowAny,)


class ProtectedCallViewSet(UserRoleMixin, ActionsViewSet, ActionMethodMixin):
    lookup_field = "uuid"
    serializer_class = serializers.ProtectedCallSerializer
    filterset_class = filters.CallFilter
    filter_backends = [DjangoFilterBackend]
    destroy_validators = [core_validators.StateValidator(CallStates.DRAFT)]

    queryset = models.Call.objects.all()

    def get_queryset(self):
        return filter_queryset_for_user(
            super().get_queryset(), self.request.user
        ).order_by("created")

    @extend_schema(
        methods=["get"],
        operation_id="proposal_protected_calls_offerings_list",
        request=None,
        responses=serializers.RequestedOfferingSerializer(many=True),
        description="List offerings for a call.",
        parameters=[
            OpenApiParameter(
                "state", str, OpenApiParameter.QUERY, description="Filter by state"
            ),
        ],
        filters=False,
    )
    @extend_schema(
        methods=["post"],
        operation_id="proposal_protected_calls_offerings_set",
        request=serializers.RequestedOfferingSerializer,
        responses=serializers.RequestedOfferingSerializer,
        description="Create offering for a call.",
    )
    @decorators.action(detail=True, methods=["get", "post"])
    def offerings(self, request, uuid=None):
        if request.method == "GET":
            call = self.get_object()
            queryset = call.requestedoffering_set.all()

            # Apply state filter if provided - only filter with valid states
            state_filter = request.query_params.getlist("state")
            if state_filter:
                # Get valid state values from the enum
                valid_states = {choice[0] for choice in RequestedOfferingStates.CHOICES}
                # Filter to only include valid state values
                valid_state_filter = [s for s in state_filter if s in valid_states]
                if valid_state_filter:
                    queryset = queryset.filter(state__in=valid_state_filter)

            serializer = self.get_serializer(
                queryset,
                context=self.get_serializer_context(),
                many=True,
            )
            return response.Response(serializer.data, status=status.HTTP_200_OK)

        return self.action_list_method("requestedoffering_set")(self, request, uuid)

    offerings_serializer_class = serializers.RequestedOfferingSerializer

    def offering_detail(self, request, uuid=None, obj_uuid=None):
        return self.action_detail_method(
            "requestedoffering_set",
            delete_validators=[],
            update_validators=[
                core_validators.StateValidator(
                    models.RequestedOffering.States.REQUESTED
                )
            ],
        )(self, request, uuid, obj_uuid)

    offering_detail_serializer_class = serializers.RequestedOfferingSerializer

    @extend_schema(
        description="Activate a call.",
        request=None,
    )
    @decorators.action(detail=True, methods=["post"])
    def activate(self, request, uuid=None):
        call: models.Call = self.get_object()
        if call.round_set.count() == 0:
            raise exceptions.ValidationError(
                _("Call must have a round to be activated.")
            )
        call.state = CallStates.ACTIVE
        call.save()
        return response.Response(
            "Call has been activated.",
            status=status.HTTP_200_OK,
        )

    activate_validators = [
        core_validators.StateValidator(CallStates.DRAFT, CallStates.ARCHIVED)
    ]

    @extend_schema(
        description="Archive a call.",
        request=None,
    )
    @decorators.action(detail=True, methods=["post"])
    def archive(self, request, uuid=None):
        call: models.Call = self.get_object()
        call.state = CallStates.ARCHIVED
        call.save()
        return response.Response(
            "Call has been archived.",
            status=status.HTTP_200_OK,
        )

    archive_validators = [
        core_validators.StateValidator(CallStates.DRAFT, CallStates.ACTIVE)
    ]

    @extend_schema(
        methods=["get"],
        operation_id="proposal_protected_calls_rounds_list",
        request=None,
        responses=serializers.ProtectedRoundSerializer(many=True),
        description="List rounds for a call.",
        filters=False,
    )
    @extend_schema(
        methods=["post"],
        operation_id="proposal_protected_calls_rounds_set",
        request=serializers.ProtectedRoundSerializer,
        responses=serializers.ProtectedRoundSerializer,
        description="Create a round for a call.",
    )
    @decorators.action(detail=True, methods=["get", "post"])
    def rounds(self, request, uuid=None):
        # TODO: Will be better move this to method of serializer and add tests.
        call: models.Call = self.get_object()
        method = self.request.method

        if method == "POST":
            repeat = request.query_params.get("repeat", "false")
            count = request.query_params.get("count", "1")

            if repeat in ["true", "True"] and int(count) > 1:
                cutoff_time_str = request.data.get("cutoff_time")
                start_time_str = request.data.get("start_time")

                cutoff_time = datetime.strptime(cutoff_time_str, "%Y-%m-%dT%H:%M")
                start_time = datetime.strptime(start_time_str, "%Y-%m-%dT%H:%M")

                duration = cutoff_time - start_time
                data = request.data.copy()
                all_created_data = []

                for i in range(int(count)):
                    new_start_time = start_time + i * duration
                    new_cutoff_time = cutoff_time + i * duration

                    data["start_time"] = new_start_time.strftime("%Y-%m-%dT%H:%M:%S%z")
                    data["cutoff_time"] = new_cutoff_time.strftime(
                        "%Y-%m-%dT%H:%M:%S%z"
                    )

                    serializer = self.get_serializer(
                        context=self.get_serializer_context(),
                        data=data,
                    )
                    serializer.is_valid(raise_exception=True)
                    serializer.save(call=call)
                    all_created_data.append(serializer.data)
                    logger.info(
                        f"Round is created with start_time: {new_start_time}, cutoff_time: {new_cutoff_time}"
                    )
                return response.Response(
                    all_created_data,
                    status=status.HTTP_201_CREATED,
                )
            else:
                serializer = self.get_serializer(
                    context=self.get_serializer_context(),
                    data=self.request.data,
                )
                serializer.is_valid(raise_exception=True)
                serializer.save(call=call)
                return response.Response(
                    serializer.data,
                    status=status.HTTP_201_CREATED,
                )
        queryset = call.round_set.all().order_by("-start_time")

        return response.Response(
            self.get_serializer(
                queryset,
                context=self.get_serializer_context(),
                many=True,
            ).data,
            status=status.HTTP_200_OK,
        )

    rounds_serializer_class = serializers.ProtectedRoundSerializer

    def round_detail(self, request, uuid=None, obj_uuid=None):
        def validate_call_state(call_round):
            if call_round.call.state == CallStates.ARCHIVED:
                raise IncorrectStateException()

        def validate_existing_of_proposals(call_round):
            if call_round.proposal_set.exclude(
                state__in=[
                    ProposalStates.CANCELED,
                    ProposalStates.REJECTED,
                ]
            ).exists():
                raise IncorrectStateException()

        return self.action_detail_method(
            "round_set",
            delete_validators=[validate_call_state, validate_existing_of_proposals],
            update_validators=[validate_call_state],
        )(self, request, uuid, obj_uuid)

    round_detail_serializer_class = serializers.ProtectedRoundSerializer

    def close_round(self, request, uuid=None, obj_uuid=None):
        call: models.Call = self.get_object()

        try:
            call_round = call.round_set.get(uuid=obj_uuid)
        except models.Round.DoesNotExist:
            return response.Response(status=status.HTTP_404_NOT_FOUND)

        permissions_utils.permission_factory(PermissionEnum.CLOSE_ROUNDS, "*")(
            request, self, call
        )

        if call_round.call.state != CallStates.ACTIVE:
            raise exceptions.ValidationError(_("Call is not active."))

        if call_round.start_time > timezone.now():
            call_round.start_time = timezone.now()

        if call_round.cutoff_time < timezone.now():
            call_round.cutoff_time = timezone.now()

        utils.create_reviews_of_round(call_round)

        return response.Response(
            "Round has been closed.",
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        request=serializers.CallAttachDocumentsSerializer,
        responses=None,
        description="Attach documents to call.",
    )
    @decorators.action(detail=True, methods=["post"])
    def attach_documents(self, request, uuid=None):
        instance: models.Call = self.get_object()

        try:
            documents = request.data.getlist("documents", [])
        except AttributeError:
            documents = request.data.get("documents", [])

            if not isinstance(documents, list):
                documents = [documents]

        description = request.data.get("description", "")

        for file_data in documents:
            obj, created = models.CallDocument.objects.get_or_create(
                call=instance,
                file=file_data,
                description=description,
            )
            if created:
                instance.documents.add(obj)
                event_logger.emit(
                    f"Attachment for call {instance.name} has been added.",
                    event_type=EventType.CALL_DOCUMENT_ADDED,
                    event_context={"call": instance},
                    scopes=[_get_customer(instance)],
                )
                logger.info(f"Attachment for {instance.name} has been added.")

        return response.Response(
            "Documents attached successfully",
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        request=serializers.CallDetachDocumentsSerializer,
        responses=None,
        description="Detach documents from call.",
    )
    @decorators.action(detail=True, methods=["post"])
    def detach_documents(self, request, uuid=None):
        instance: models.Call = self.get_object()

        try:
            documents = request.data.getlist("documents", [])
        except AttributeError:
            documents = request.data.get("documents", [])

            if not isinstance(documents, list):
                documents = [documents]

        logger.info(f"Removing documents {documents} from call {instance.name}")

        for file_data in documents:
            models.CallDocument.objects.get(
                call=instance,
                uuid=file_data,
            ).delete()
            event_logger.emit(
                f"Attachment for call {instance.name} has been removed.",
                event_type=EventType.CALL_DOCUMENT_REMOVED,
                event_context={"call": instance},
                scopes=[_get_customer(instance)],
            )
            logger.info(f"Attachment for {instance.name} has been removed.")

        return response.Response(
            "Documents removed successfully",
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        methods=["get"],
        operation_id="proposal_protected_calls_resource_templates_list",
        request=None,
        responses=serializers.CallResourceTemplateSerializer(many=True),
        description="List resource templates for a call.",
        filters=False,
    )
    @extend_schema(
        methods=["post"],
        operation_id="proposal_protected_calls_resource_templates_set",
        request=serializers.CallResourceTemplateSerializer,
        responses=serializers.CallResourceTemplateSerializer,
        description="Create resource template for a call.",
    )
    @decorators.action(detail=True, methods=["get", "post"])
    def resource_templates(self, request, uuid=None):
        return self.action_list_method("resource_templates")(self, request, uuid)

    resource_templates_serializer_class = serializers.CallResourceTemplateSerializer

    def resource_template_detail(self, request, uuid=None, obj_uuid=None):
        return self.action_detail_method(
            "resource_templates", delete_validators=[], update_validators=[]
        )(self, request, uuid, obj_uuid)

    resource_template_detail_serializer_class = (
        serializers.CallResourceTemplateSerializer
    )

    # Call Manager Compliance Endpoints
    compliance_overview_permissions = [permission_factory(PermissionEnum.UPDATE_CALL)]

    @extend_schema(
        description="Get compliance overview for call manager showing all proposals and their compliance status.",
        responses=serializers.CallComplianceOverviewSerializer,
    )
    @decorators.action(detail=True, methods=["get"])
    def compliance_overview(self, request, uuid=None):
        """Get compliance overview for call manager."""
        call = self.get_object()

        if not call.compliance_checklist:
            return response.Response(
                {
                    "detail": "No compliance checklist configured for this call",
                    "checklist": None,
                    "proposals": [],
                }
            )

        # Serialize the compliance overview
        overview_data = serializers.CallComplianceOverviewSerializer(
            call, context={"request": request}
        ).data

        return response.Response(overview_data)

    review_proposal_compliance_permissions = [
        permission_factory(PermissionEnum.UPDATE_CALL)
    ]

    @extend_schema(
        description="Mark proposal compliance as reviewed by call manager.",
        request=serializers.CallComplianceReviewSerializer,
        responses=dict[str, str],
    )
    @decorators.action(detail=True, methods=["post"])
    def review_proposal_compliance(self, request, uuid=None):
        """Mark proposal compliance as reviewed by call manager."""
        call = self.get_object()

        # Validate input
        serializer = serializers.CallComplianceReviewSerializer(
            data=request.data, context={"call": call, "request": request}
        )
        serializer.is_valid(raise_exception=True)

        proposal_uuid = serializer.validated_data["proposal_uuid"]
        review_notes = serializer.validated_data.get("review_notes", "")

        try:
            proposal: Proposal = Proposal.objects.get(
                round__call=call, uuid=proposal_uuid
            )
            completion = proposal.checklist_completion

            completion.reviewed_by = request.user
            completion.reviewed_at = timezone.now()
            completion.review_notes = review_notes
            completion.save()

            return response.Response(
                {
                    "detail": "Compliance review completed successfully",
                    "proposal_uuid": str(proposal_uuid),
                    "reviewed_by": request.user.full_name,
                    "reviewed_at": completion.reviewed_at,
                }
            )

        except models.Proposal.DoesNotExist:
            return response.Response(
                {"detail": "Proposal not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except checklist_models.ChecklistCompletion.DoesNotExist:
            return response.Response(
                {"detail": "Proposal has no compliance checklist"},
                status=status.HTTP_400_BAD_REQUEST,
            )

    proposal_compliance_answers_permissions = [
        permission_factory(PermissionEnum.UPDATE_CALL)
    ]

    @extend_schema(
        description="Get detailed compliance answers for a specific proposal (call managers only).",
        responses=checklist_serializers.AnswerSerializer(many=True),
        parameters=[
            OpenApiParameter(
                name="proposal_uuid",
                type=str,
                location=OpenApiParameter.PATH,
                description="UUID of the proposal",
            )
        ],
    )
    @decorators.action(
        detail=True,
        methods=["get"],
        url_path="proposals/(?P<proposal_uuid>[^/.]+)/compliance-answers",
    )
    def proposal_compliance_answers(self, request, uuid=None, proposal_uuid=None):
        """Get detailed compliance answers for a specific proposal."""
        call: models.Call = self.get_object()

        try:
            proposal = models.Proposal.objects.get(uuid=proposal_uuid, round__call=call)

            if not hasattr(proposal, "checklist_completion"):
                return response.Response(
                    {"detail": "Proposal has no compliance checklist"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            completion = proposal.checklist_completion
            answers = completion.answers.all().select_related("question", "user")

            answers_data = checklist_serializers.AnswerSerializer(
                answers, many=True, context={"request": request}
            ).data

            return response.Response(
                {
                    "proposal": {
                        "uuid": str(proposal.uuid),
                        "name": proposal.name,
                        "created_by": proposal.created_by.full_name
                        if proposal.created_by
                        else None,
                    },
                    "completion": checklist_serializers.ChecklistCompletionReviewerSerializer(
                        completion, context={"request": request}
                    ).data,
                    "answers": answers_data,
                }
            )

        except models.Proposal.DoesNotExist:
            return response.Response(
                {"detail": "Proposal not found"}, status=status.HTTP_404_NOT_FOUND
            )


class ProposalViewSet(
    UserChecklistMixin,
    ReviewerChecklistMixin,
    UserRoleMixin,
    ActionsViewSet,
    ActionMethodMixin,
):
    lookup_field = "uuid"
    serializer_class = serializers.ProposalSerializer
    filterset_class = filters.ProposalFilter
    disabled_actions = ["update", "partial_update"]
    model = models.Proposal

    def get_queryset(self):
        return filter_queryset_for_user(
            models.Proposal.objects.all(), self.request.user
        ).order_by("created")

    # Both mixins use the default implementation (obj.checklist_completion)

    # UserChecklistMixin permissions - for proposal managers
    checklist_permissions = [permission_factory(PermissionEnum.MANAGE_PROPOSAL)]
    completion_status_permissions = [permission_factory(PermissionEnum.MANAGE_PROPOSAL)]
    submit_answers_permissions = [permission_factory(PermissionEnum.MANAGE_PROPOSAL)]

    # ReviewerChecklistMixin permissions - for proposal reviewers
    checklist_review_permissions = [
        permission_factory(PermissionEnum.MANAGE_PROPOSAL_REVIEW, ["round.call"])
    ]
    completion_review_status_permissions = [
        permission_factory(PermissionEnum.MANAGE_PROPOSAL_REVIEW, ["round.call"])
    ]

    def is_creator(request, view, obj=None):
        if not obj:
            return
        user = request.user
        if obj.created_by == user or user.is_staff:
            return
        raise exceptions.PermissionDenied()

    destroy_permissions = update_project_details_permissions = [is_creator]

    destroy_validators = update_project_details_validators = [
        core_validators.StateValidator(ProposalStates.DRAFT)
    ]

    update_project_details_serializer_class = (
        serializers.ProposalUpdateProjectDetailsSerializer
    )

    @extend_schema(
        description="Update project details of a proposal.",
        request=serializers.ProposalUpdateProjectDetailsSerializer,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def update_project_details(self, request, uuid=None):
        proposal = self.get_object()
        serializer = self.get_serializer(data=request.data, instance=proposal)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return response.Response(status=status.HTTP_200_OK)

    @staticmethod
    def validate_resource_requests_existing(proposal):
        if not models.RequestedResource.objects.filter(proposal=proposal).exists():
            raise exceptions.ValidationError(
                _(
                    "There must be at least some resource requests existing before moving to team validation."
                )
            )

    @extend_schema(
        description="Submit a proposal.",
        request=None,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def submit(self, request, uuid=None):
        proposal = self.get_object()
        previous_state = proposal.state
        proposal.state = ProposalStates.SUBMITTED
        proposal.save()
        tasks.notify_user_about_proposal_state_update.delay(
            proposal.uuid, previous_state, proposal.state
        )
        tasks.notify_call_managers_about_new_proposal_submission.delay(proposal.uuid)
        return response.Response(
            "Proposal has been submitted.",
            status=status.HTTP_200_OK,
        )

    submit_validators = [core_validators.StateValidator(ProposalStates.DRAFT)]

    submit_permissions = [is_creator]

    def perform_create(self, serializer):
        proposal: models.Proposal = serializer.save()
        proposal.add_user(
            self.request.user,
            ProposalRole.MANAGER,
            created_by=self.request.user,
        )

    @extend_schema(
        methods=["get"],
        operation_id="proposal_proposals_resources_list",
        request=None,
        responses=serializers.RequestedResourceSerializer(many=True),
        description="List resources for a proposal.",
        filters=False,
    )
    @extend_schema(
        methods=["post"],
        operation_id="proposal_proposals_resources_set",
        request=serializers.RequestedResourceSerializer,
        responses=serializers.RequestedResourceSerializer,
        description="Create resource for a proposal.",
    )
    @decorators.action(detail=True, methods=["get", "post"])
    def resources(self, request, uuid=None):
        return self.action_list_method("requestedresource_set")(self, request, uuid)

    resources_serializer_class = serializers.RequestedResourceSerializer

    def resource_detail(self, request, uuid=None, obj_uuid=None):
        def validate_proposal_state(requested_resource):
            if requested_resource.proposal.state != ProposalStates.DRAFT:
                raise IncorrectStateException(
                    "Only proposals with a draft status are available for editing."
                )

        return self.action_detail_method(
            "requestedresource_set",
            delete_validators=[validate_proposal_state],
            update_validators=[validate_proposal_state],
        )(self, request, uuid, obj_uuid)

    resource_detail_serializer_class = serializers.RequestedResourceSerializer

    @extend_schema(
        description="Attach document to proposal.",
        request=serializers.ProposalDocumentationSerializer,
        responses=None,
    )
    @decorators.action(detail=True, methods=["post"])
    def attach_document(self, request, uuid=None):
        proposal = cast(models.Proposal, self.get_object())
        serializer = self.get_serializer(
            context=self.get_serializer_context(),
            data=request.data,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save(proposal=proposal)

        event_logger.emit(
            f"Attachment for proposal {proposal.name} has been added.",
            event_type=EventType.PROPOSAL_DOCUMENT_ADDED,
            event_context={"proposal": proposal},
            scopes=[_get_customer(proposal)],
        )
        return response.Response(status=status.HTTP_200_OK)

    attach_document_serializer_class = serializers.ProposalDocumentationSerializer

    @extend_schema(
        description="Detach document from proposal.",
        request=serializers.ProposalDetachDocumentSerializer,
        responses={
            status.HTTP_200_OK: None,
            status.HTTP_404_NOT_FOUND: None,
            status.HTTP_403_FORBIDDEN: None,
        },
    )
    @decorators.action(detail=True, methods=["post"])
    def detach_document(self, request, uuid=None):
        """
        Remove a document from a proposal.

        Only allowed when proposal is in draft state.
        Deletes both the database record and the physical file.
        """
        proposal = cast(models.Proposal, self.get_object())

        # Get the file path/URL from request
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        file_identifier = serializer.validated_data["file"]

        # The frontend can send:
        # - UUID-based media URL: /api/media/{uuid}/
        # - Direct file URL: /media/proposal_project.../file.pdf
        # - Full URL with domain

        # Try to extract UUID from the file identifier
        import re

        uuid_pattern = re.compile(
            r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?"
            r"[0-9a-f]{4}-?[0-9a-f]{12}",
            re.IGNORECASE,
        )
        uuid_match = uuid_pattern.search(file_identifier)

        document = None
        file = None

        # Try UUID-based lookup first (most common case)
        if uuid_match:
            uuid_str = uuid_match.group().replace("-", "")
            # Format as proper UUID with dashes
            formatted_uuid = (
                f"{uuid_str[:8]}-{uuid_str[8:12]}-"
                f"{uuid_str[12:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"
            )

            try:
                file = media_models.File.objects.get(uuid=formatted_uuid)
            except media_models.File.DoesNotExist:
                return response.Response(
                    {"detail": "File not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            try:
                media_views.check_file_permissions(file, request.user)
            except exceptions.PermissionDenied:
                logger.warning(
                    f"User {request.user} tried to detach file {file.uuid} "
                    f"without having permission to access it."
                )
                file = None

            # Now find the ProposalDocumentation that matches this file (by UUID)
            for doc in models.ProposalDocumentation.objects.filter(proposal=proposal):
                if formatted_uuid in str(doc.file.url) or uuid_str in str(doc.file.url):
                    document = doc
                    logger.info(f"Found by UUID: {document.file.name}")
                    break

            if document is None:
                logger.info(
                    f"File with UUID {formatted_uuid} not found in proposal {proposal.uuid}"
                )

        # Fallback: try file path matching
        if not document:
            # Normalize file path
            normalized_path = file_identifier
            if "/media/" in file_identifier:
                normalized_path = file_identifier.split("/media/", 1)[1]
            elif file_identifier.startswith("http://") or file_identifier.startswith(
                "https://"
            ):
                from urllib.parse import urlparse

                parsed = urlparse(file_identifier)
                if "/media/" in parsed.path:
                    normalized_path = parsed.path.split("/media/", 1)[1]
                else:
                    normalized_path = parsed.path.lstrip("/")

            # Remove trailing slashes
            normalized_path = normalized_path.rstrip("/")

            documents = models.ProposalDocumentation.objects.filter(proposal=proposal)

            # Try exact path match
            document = documents.filter(file=normalized_path).first()
            if document:
                logger.info(f"Found by exact path: {document.file.name}")

            # Try matching by file.name
            if not document:
                for doc in documents:
                    if doc.file.name == normalized_path:
                        document = doc
                        logger.info(f"Found by name: {doc.file.name}")
                        break

        if not document:
            logger.warning(
                f"Document '{file_identifier}' not found for proposal {proposal.uuid}"
            )
            return response.Response(
                {"detail": "File not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Delete the document (file deleted via FileField behavior)
        logger.info(
            f"Removing document {document.uuid} "
            f"(file: {document.file.name}) from proposal {proposal.name}"
        )
        document.delete()

        if file:
            if str(file.name) == str(document.file.name):
                # this file is only used by this document
                logger.info(
                    f"Deleting file {file.uuid} with name {file.name} from storage"
                )
                file.delete()
            else:
                logger.info(
                    f"File {file.uuid} with name {file.name} is used by other records, not deleting"
                )

        event_logger.emit(
            f"Attachment for proposal {proposal.name} has been removed.",
            event_type=EventType.PROPOSAL_DOCUMENT_REMOVED,
            event_context={"proposal": proposal},
            scopes=[_get_customer(proposal)],
        )

        return response.Response(
            {"detail": "Document removed successfully"},
            status=status.HTTP_200_OK,
        )

    detach_document_serializer_class = serializers.ProposalDetachDocumentSerializer

    detach_document_validators = [core_validators.StateValidator(ProposalStates.DRAFT)]

    detach_document_permissions = [is_creator]

    @extend_schema(
        description="Approve a proposal.",
        request=serializers.ProposalApproveSerializer,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def approve(self, request, uuid=None):
        proposal = self.get_object()
        previous_state = proposal.state
        utils.allocate_proposal(proposal)
        proposal.state = ProposalStates.ACCEPTED
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        proposal.allocation_comment = serializer.validated_data.get(
            "allocation_comment", ""
        )
        proposal.save()

        # Delete stale review requests that are no longer needed
        stale_reviews = proposal.review_set.filter(
            state__in=[models.Review.States.CREATED, models.Review.States.IN_REVIEW]
        )
        stale_count = stale_reviews.count()
        if stale_count > 0:
            logger.info(
                f"Deleting {stale_count} stale review request(s) "
                f"for approved proposal {proposal.uuid}"
            )
            stale_reviews.delete()

        tasks.notify_user_about_proposal_state_update.delay(
            proposal.uuid, previous_state, proposal.state
        )
        tasks.notify_reviewer_on_proposal_decision.delay(proposal.uuid)
        return response.Response(
            "Proposal has been approved.",
            status=status.HTTP_200_OK,
        )

    approve_validators = [
        core_validators.StateValidator(
            ProposalStates.SUBMITTED,
            ProposalStates.IN_REVIEW,
            ProposalStates.REJECTED,
            state_enum=ReviewStates,
        )
    ]

    @extend_schema(
        description="Reject a proposal.",
        request=serializers.ProposalApproveSerializer,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def reject(self, request, uuid=None):
        proposal = self.get_object()
        previous_state = proposal.state
        proposal.state = ProposalStates.REJECTED
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        proposal.allocation_comment = serializer.validated_data.get(
            "allocation_comment", ""
        )
        proposal.save()

        # Delete stale review requests that are no longer needed
        stale_reviews = proposal.review_set.filter(
            state__in=[models.Review.States.CREATED, models.Review.States.IN_REVIEW]
        )
        stale_count = stale_reviews.count()
        if stale_count > 0:
            logger.info(
                f"Deleting {stale_count} stale review request(s) "
                f"for rejected proposal {proposal.uuid}"
            )
            stale_reviews.delete()

        tasks.notify_user_about_proposal_state_update.delay(
            proposal.uuid, previous_state, proposal.state
        )
        tasks.notify_reviewer_on_proposal_decision.delay(proposal.uuid)
        return response.Response(
            "Proposal has been rejected.",
            status=status.HTTP_200_OK,
        )

    reject_validators = [
        core_validators.StateValidator(
            ProposalStates.SUBMITTED,
            ProposalStates.IN_REVIEW,
        )
    ]
    reject_permissions = approve_permissions = [
        permission_factory(
            PermissionEnum.APPROVE_AND_REJECT_PROPOSALS,
            ["round.call", "round.call.manager"],
        )
    ]
    reject_serializer_class = approve_serializer_class = (
        serializers.ProposalApproveSerializer
    )

    @extend_schema(
        description="Return proposal to applicant for revision.",
        request=serializers.ProposalApproveSerializer,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def return_to_applicant(self, request, uuid=None):
        proposal = self.get_object()
        previous_state = proposal.state
        proposal.state = ProposalStates.DRAFT
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        proposal.allocation_comment = serializer.validated_data.get(
            "allocation_comment", ""
        )
        proposal.save()

        # Delete stale review requests that are no longer needed
        stale_reviews = proposal.review_set.filter(
            state__in=[models.Review.States.CREATED, models.Review.States.IN_REVIEW]
        )
        stale_count = stale_reviews.count()
        if stale_count > 0:
            logger.info(
                f"Deleting {stale_count} stale review request(s) "
                f"for returned proposal {proposal.uuid}"
            )
            stale_reviews.delete()

        tasks.notify_user_about_proposal_state_update.delay(
            proposal.uuid, previous_state, proposal.state
        )
        return response.Response(
            "Proposal has been returned to applicant for revision.",
            status=status.HTTP_200_OK,
        )

    return_to_applicant_validators = [
        core_validators.StateValidator(
            ProposalStates.SUBMITTED,
            ProposalStates.IN_REVIEW,
        )
    ]
    return_to_applicant_permissions = [
        permission_factory(
            PermissionEnum.APPROVE_AND_REJECT_PROPOSALS,
            ["round.call", "round.call.manager"],
        )
    ]
    return_to_applicant_serializer_class = serializers.ProposalApproveSerializer

    # Checklist Integration Endpoints
    # Checklist methods are now provided by ChecklistViewSetMixin
    # - checklist: Get checklist with questions and existing answers
    # - submit_answers: Submit checklist answers
    # - completion_status: Get completion status


class ReviewViewSet(ActionsViewSet):
    lookup_field = "uuid"
    serializer_class = serializers.ProposalReviewSerializer
    filterset_class = filters.ReviewFilter
    queryset = models.Review.objects.all()

    update_validators = partial_update_validators = [
        core_validators.StateValidator(
            models.Review.States.CREATED, models.Review.States.IN_REVIEW
        )
    ]

    def get_queryset(self):
        user = self.request.user

        if user.is_staff:
            return models.Review.objects.all().order_by("created")

        # Base queries for authorized users (call organizers, call managers, reviewers)
        authorized_query = (
            Q(
                proposal__round__call__manager__customer__callmanagingorganisation__in=get_connected_call_organizers(
                    user
                )
            )
            | Q(
                proposal__round__call__manager__customer__in=get_connected_customers(
                    user
                )
            )
            | Q(proposal__round__call__in=get_connected_calls(user, CallRole.MANAGER))
            | Q(reviewer=user)
        )

        # For proposal submitters - apply visibility controls
        submitter_query = Q(proposal__created_by=user)

        # Key change: Only include reviews for submitters if reviews are visible in the call
        submitter_query &= Q(proposal__round__call__reviews_visible_to_submitters=True)

        # Only show submitted reviews to submitters (existing logic)
        submitter_query &= Q(state=models.Review.States.SUBMITTED)

        # For submitters, reviews are visible only if the proposal has a decision state
        submitter_query &= Q(
            proposal__state__in=[
                models.Proposal.States.ACCEPTED,
                models.Proposal.States.REJECTED,
            ]
        )

        return models.Review.objects.filter(
            authorized_query | submitter_query
        ).order_by("created")

    def perform_create(self, serializer):
        proposal = serializer.validated_data["proposal"]
        if proposal.state not in [
            ProposalStates.DRAFT,
            ProposalStates.IN_REVIEW,
            ProposalStates.SUBMITTED,
        ]:
            raise exceptions.ValidationError(
                _("Valid states for proposals: Draft, In Review, Submitted.")
            )
        review: models.Review = serializer.save()
        tasks.notify_reviewer_about_assignment.delay(review.uuid)

    def check_create_permissions(request, view, obj=None):
        """Check permissions for creating reviews."""
        serializer = view.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        proposal = serializer.validated_data["proposal"]

        user = request.user
        permission = PermissionEnum.MANAGE_PROPOSAL_REVIEW
        call = proposal.round.call

        if not (
            has_permission(user, permission, call)
            or has_permission(user, permission, call.manager)
        ):
            raise exceptions.PermissionDenied()

    def check_destroy_permissions(request, view, obj=None):
        """Check permissions for destroying reviews."""
        if obj and not (
            has_permission(
                request.user,
                PermissionEnum.MANAGE_PROPOSAL_REVIEW,
                obj.proposal.round.call,
            )
            or has_permission(
                request.user,
                PermissionEnum.MANAGE_PROPOSAL_REVIEW,
                obj.proposal.round.call.manager,
            )
        ):
            raise exceptions.PermissionDenied()

    create_permissions = [check_create_permissions]
    destroy_permissions = [check_destroy_permissions]

    def action_permission_check(request, view, obj: models.Review | None = None):
        if not obj:
            return

        user = request.user

        if user.is_staff or obj.reviewer == user:
            return

        raise exceptions.PermissionDenied()

    @extend_schema(
        description="Accept a review, changing its state to IN_REVIEW.",
        request=None,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def accept(self, request, uuid=None):
        review: models.Review = self.get_object()
        review.state = models.Review.States.IN_REVIEW
        review.save()
        proposal_old_state = review.proposal.state
        review.proposal.state = ProposalStates.IN_REVIEW
        review.proposal.save()
        logger.info(
            f"Review {review.uuid}, by {review.reviewer.full_name} for proposal {review.proposal.name} has been accepted. Proposal state changed to IN_REVIEW."
        )
        tasks.notify_user_about_proposal_state_update.delay(
            review.proposal.uuid, proposal_old_state, review.proposal.state
        )
        return response.Response(
            "Review has been accepted.",
            status=status.HTTP_200_OK,
        )

    accept_validators = [
        core_validators.StateValidator(models.Review.States.CREATED),
    ]

    @extend_schema(
        description="Reject a review, changing its state to REJECTED.",
        request=None,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def reject(self, request, uuid=None):
        review: models.Review = self.get_object()
        review.state = models.Review.States.REJECTED
        review.save()
        tasks.notify_call_managers_about_rejected_review.delay(review.uuid)
        return response.Response(
            "Review has been rejected.",
            status=status.HTTP_200_OK,
        )

    reject_validators = [
        core_validators.StateValidator(
            models.Review.States.CREATED, models.Review.States.IN_REVIEW
        ),
    ]

    @extend_schema(
        description="Submit a review, changing its state to SUBMITTED.",
        request=ReviewSubmitSerializer,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def submit(self, request, uuid=None):
        review: models.Review = self.get_object()
        serializer = ReviewSubmitSerializer(
            instance=review, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save(state=models.Review.States.SUBMITTED)
        tasks.notify_call_managers_about_new_review.delay(review.uuid)
        tasks.notify_manager_when_reviews_are_completed.delay(review.proposal.uuid)
        return response.Response(
            "Review has been submitted.",
            status=status.HTTP_200_OK,
        )

    submit_validators = [
        core_validators.StateValidator(models.Review.States.IN_REVIEW),
    ]
    accept_permissions = reject_permissions = submit_permissions = (
        update_permissions
    ) = partial_update_permissions = [action_permission_check]


class ProviderRequestedOfferingViewSet(ReadOnlyActionsViewSet):
    lookup_field = "uuid"
    queryset = models.RequestedOffering.objects.filter().order_by(
        "offering", "call", "created"
    )
    serializer_class = serializers.ProviderRequestedOfferingSerializer
    filterset_class = filters.RequestedOfferingFilter
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)

    @extend_schema(
        description="Accept a requested offering.",
        request=None,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def accept(self, request, uuid=None):
        requested_offering: models.RequestedOffering = self.get_object()
        requested_offering.state = RequestedOfferingStates.ACCEPTED
        requested_offering.approved_by = self.request.user
        requested_offering.save()
        tasks.notify_offering_request_decision.delay(requested_offering.uuid)
        return response.Response(
            "The request on offering has been accepted.",
            status=status.HTTP_200_OK,
        )

    accept_validators = [
        core_validators.StateValidator(RequestedOfferingStates.REQUESTED)
    ]

    @extend_schema(
        description="Cancel a requested offering.",
        request=None,
        responses={status.HTTP_200_OK: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def cancel(self, request, uuid=None):
        requested_offering: models.RequestedOffering = self.get_object()
        requested_offering.state = RequestedOfferingStates.CANCELED
        requested_offering.approved_by = self.request.user
        requested_offering.save()
        tasks.notify_offering_request_decision.delay(requested_offering.uuid)
        return response.Response(
            "The request on offering has been canceled.",
            status=status.HTTP_200_OK,
        )

    cancel_validators = [
        core_validators.StateValidator(RequestedOfferingStates.REQUESTED)
    ]

    accept_permissions = cancel_permissions = [
        proposal_permissions.user_can_accept_requested_offering
    ]


class ProviderRequestedResourceViewSet(ReadOnlyActionsViewSet):
    lookup_field = "uuid"
    serializer_class = serializers.ProviderRequestedResourceSerializer
    filterset_class = filters.RequestedResourceFilter
    filter_backends = (DjangoFilterBackend,)

    def get_queryset(self):
        user = self.request.user

        if user.is_staff:
            return models.RequestedResource.objects.all().order_by(
                "resource", "proposal", "created"
            )

        offerings_ids = (
            marketplace_models.Offering.objects.all()
            .filter_for_user(user)
            .values_list("id", flat=True)
        )
        return models.RequestedResource.objects.filter(
            requested_offering__offering_id__in=offerings_ids
        ).order_by("resource", "proposal", "created")


class RoundViewSet(ReadOnlyActionsViewSet):
    lookup_field = "uuid"
    serializer_class = serializers.CallRoundSerializer
    filterset_class = []
    filter_backends = (DjangoFilterBackend,)

    def get_queryset(self):
        return filter_queryset_for_user(models.Round.objects.all(), self.request.user)

    @extend_schema(
        description="Return list of reviewers for round.",
        request=None,
        responses=serializers.RoundReviewerSerializer(many=True),
    )
    @decorators.action(detail=True)
    def reviewers(self, request, uuid=None):
        round_obj = self.get_object()

        unique_reviewer_ids = (
            models.Review.objects.filter(proposal__round=round_obj)
            .values_list("reviewer", flat=True)
            .distinct()
        )
        users = User.objects.filter(id__in=unique_reviewer_ids)

        proposals = models.Proposal.objects.filter(
            review__reviewer=OuterRef("pk"), round=round_obj
        )

        accepted_proposals_subquery = proposals.filter(
            state=ProposalStates.ACCEPTED
        ).values("pk")

        rejected_proposals_subquery = proposals.filter(
            state=ProposalStates.REJECTED
        ).values("pk")

        in_review_proposals_subquery = proposals.filter(
            state=ProposalStates.IN_REVIEW
        ).values("pk")

        users = users.annotate(
            accepted_proposals=Coalesce(SubqueryCount(accepted_proposals_subquery), 0),
            rejected_proposals=Coalesce(SubqueryCount(rejected_proposals_subquery), 0),
            in_review_proposals=Coalesce(
                SubqueryCount(in_review_proposals_subquery), 0
            ),
        )

        page = self.paginate_queryset(users)
        serializer = serializers.RoundReviewerSerializer(
            page, many=True, context={"round_obj": round_obj}
        )
        return self.get_paginated_response(serializer.data)


class ProposalProjectRoleMappingViewSet(ActionsViewSet):
    lookup_field = "uuid"
    serializer_class = serializers.ProposalProjectRoleMappingSerializer
    queryset = models.ProposalProjectRoleMapping.objects.all().order_by("call")
    filterset_class = filters.ProposalProjectRoleMappingFilter
    filter_backends = (DjangoFilterBackend,)
    permission_classes = [proposal_permissions.CanUpdateCallPermission]


class ProposalUserViewSet(viewsets.GenericViewSet):
    """
    ViewSet for creating or retrieving users for proposals.

    POST /api/proposal-add-user/
    - Accepts: email, first_name, last_name
    - Returns: User object (existing or newly created)

    This endpoint is used when building proposal teams to either find
    existing users by email or create new user accounts on-the-fly.
    """

    serializer_class = serializers.ProposalUserSerializer
    permission_classes = (rf_permissions.IsAuthenticated,)

    @extend_schema(
        request=serializers.ProposalUserSerializer,
        responses={200: serializers.ProposalUserSerializer},
        description="Create or retrieve a user for a proposal team. "
        "If a user with the given email exists, returns that user. "
        "Otherwise creates a new user account with the provided details.",
    )
    def create(self, request):
        """
        Get or create a user based on email, first_name, last_name.

        Requires authentication. Any authenticated user can use this endpoint
        to look up or create users for their proposal teams.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        # Prepare response data with all user fields
        response_serializer = self.serializer_class(user)
        return response.Response(response_serializer.data, status=status.HTTP_200_OK)
