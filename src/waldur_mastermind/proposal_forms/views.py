import logging
import uuid as uuid_lib
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.db import transaction
from django.shortcuts import redirect as http_redirect
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import extend_schema
from rest_framework import decorators, exceptions, response, status, views, viewsets
from rest_framework import permissions as rf_permissions

from waldur_core.core import utils as core_utils
from waldur_core.core.views import ActionsViewSet
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.utils import permission_factory
from waldur_core.structure.managers import filter_queryset_for_user
from waldur_core.structure.permissions import is_staff
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal.permissions import CALL_PERMISSION_SOURCES

from . import client, flows, models, responses, serializers, sync
from . import permissions as form_permissions

logger = logging.getLogger(__name__)
User = get_user_model()


def _flow_for(call):
    flow = serializers.get_call_form_flow(call)
    if flow is None:
        raise exceptions.ValidationError(_("This call does not use forms."))
    return flow


# --- connection -----------------------------------------------------------------


class FormbricksConnectionView(views.APIView):
    """The site's Formbricks server, set up through the API like an identity
    provider. Staff may change it; support may read it."""

    permission_classes = (rf_permissions.IsAuthenticated,)

    def _check(self, request):
        form_permissions.is_staff_or_support_for_reads(request, self)

    @extend_schema(
        operation_id="formbricks_connection_retrieve",
        responses=serializers.FormbricksConnectionSerializer,
    )
    def get(self, request):
        self._check(request)
        serializer = serializers.FormbricksConnectionSerializer(
            client.connection(), context={"request": request}
        )
        return response.Response(serializer.data)

    @extend_schema(
        operation_id="formbricks_connection_partial_update",
        request=serializers.FormbricksConnectionSerializer,
        responses=serializers.FormbricksConnectionSerializer,
    )
    def patch(self, request):
        self._check(request)
        with transaction.atomic():
            connection = models.FormbricksConnection.objects.select_for_update().get(
                pk=client.connection().pk
            )
            serializer = serializers.FormbricksConnectionSerializer(
                connection,
                data=request.data,
                partial=True,
                context={"request": request},
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
        # Names of what changed only: never the key or the secret.
        logger.info(
            "Formbricks connection changed by %s: %s.",
            request.user.username,
            ", ".join(sorted(serializer.validated_data)) or "nothing",
        )
        return response.Response(serializer.data)


class FormbricksConnectionTestView(views.APIView):
    permission_classes = (rf_permissions.IsAuthenticated,)

    @extend_schema(
        operation_id="formbricks_connection_test",
        request=None,
        responses=serializers.FormbricksConnectionTestSerializer,
        description="Check the Management API can be reached with the stored "
        "URL and key.",
    )
    def post(self, request):
        is_staff(request, self)
        connection = client.connection()
        if not connection.management_base_url or not connection.api_key:
            result = {"ok": False, "detail": "Set the URL and API key first."}
        else:
            try:
                count = client.check_connection(connection)
                result = {
                    "ok": True,
                    "detail": f"Connected. The key can see {count} survey(s).",
                }
            except client.FormbricksError as e:
                result = {"ok": False, "detail": str(e)}
        return response.Response(
            serializers.FormbricksConnectionTestSerializer(result).data
        )


# --- flows ------------------------------------------------------------------------


def flow_is_not_used(flow):
    if flow.call_links.exists():
        raise exceptions.ValidationError(
            _("The flow is used by a call; detach it from its calls first.")
        )


class FormFlowViewSet(ActionsViewSet):
    """Survey chains applicants fill in. Anyone signed in may read them (call
    managers choose one for their call); only staff may change them."""

    queryset = models.FormFlow.objects.all()
    serializer_class = serializers.FormFlowSerializer
    lookup_field = "uuid"
    unsafe_methods_permissions = [is_staff]
    destroy_validators = [flow_is_not_used]

    def _check_response(self, results):
        data = {"in_sync": all(r["in_sync"] for r in results), "steps": results}
        return response.Response(serializers.FormFlowCheckSerializer(data).data)

    @extend_schema(
        request=None,
        responses=serializers.FormFlowCheckSerializer,
        description="Read each step's survey from Formbricks and report what Sync "
        "would change, and anything Waldur cannot fix itself. Changes nothing.",
    )
    @decorators.action(detail=True, methods=["get"], url_path="check")
    def check_surveys(self, request, uuid=None):
        flow = self.get_object()
        return self._check_response(
            sync.check_flow(flow, request.build_absolute_uri("/"))
        )

    # Not "check": check_permissions would shadow DRF's own method.
    check_surveys_permissions = [form_permissions.is_staff_or_support_for_reads]

    @extend_schema(
        request=None,
        responses=serializers.FormFlowCheckSerializer,
        description="Make each step's survey ready in Formbricks: single-use "
        "links, the proposal_uuid hidden field, endings back to the proposal. "
        "Only those settings are written. Returns the "
        "check after the changes.",
    )
    @decorators.action(detail=True, methods=["post"])
    def sync(self, request, uuid=None):
        flow = self.get_object()
        return self._check_response(
            sync.sync_flow(flow, request.build_absolute_uri("/"), request.user)
        )

    sync_permissions = [is_staff]


class FormbricksSurveyListView(views.APIView):
    """The surveys in Formbricks the API key can reach, for choosing a flow's
    steps."""

    permission_classes = (rf_permissions.IsAuthenticated,)

    @extend_schema(
        operation_id="formbricks_surveys_list",
        responses=serializers.FormbricksSurveySerializer(many=True),
    )
    def get(self, request):
        form_permissions.is_staff_or_support_for_reads(request, self)
        try:
            surveys = client.list_surveys()
        except client.FormbricksError as e:
            raise exceptions.ValidationError(str(e))
        used_by = {}
        for flow in models.FormFlow.objects.all():
            for step in flow.steps:
                used_by.setdefault(step["survey_id"], []).append(flow.key)
        data = [
            {
                "id": survey["id"],
                "name": survey.get("name") or "",
                "type": survey.get("type") or "",
                "status": survey.get("status") or "",
                "environment_id": survey.get("environmentId") or "",
                "question_count": len(client.survey_questions(survey)),
                "updated_at": survey.get("updatedAt") or "",
                "used_by_flows": sorted(used_by.get(survey["id"], [])),
            }
            for survey in surveys
        ]
        data.sort(key=lambda s: s["name"].lower())
        return response.Response(
            serializers.FormbricksSurveySerializer(data, many=True).data
        )


class ProposalFormReturnView(views.APIView):
    """Where a survey's endings send the applicant: on to the proposal in
    HomePort, telling it which form was just finished so it can fetch the
    answers. Changes nothing, so needs no authentication."""

    authentication_classes = ()
    permission_classes = (rf_permissions.AllowAny,)

    # Not called by the frontend, so not in the API schema or the SDK.
    @extend_schema(exclude=True)
    def get(self, request):
        proposal_uuid = request.query_params.get("proposal_uuid", "")
        survey_id = request.query_params.get("survey", "")
        try:
            proposal_hex = uuid_lib.UUID(proposal_uuid).hex
        except ValueError:
            return http_redirect(core_utils.format_homeport_link("proposals/"))
        link = core_utils.format_homeport_link(
            "proposals/{proposal_uuid}/", proposal_uuid=proposal_hex
        )
        if flows.SURVEY_ID_PATTERN.match(survey_id):
            link = f"{link}?{urlencode({'form_survey': survey_id})}"
        return http_redirect(link)


# --- a call's flow ----------------------------------------------------------------


class CallFormFlowViewSet(viewsets.GenericViewSet):
    """Which flow a call's applicants fill in, by call UUID. Set by those who
    manage the call; fixed once the call has proposals."""

    lookup_field = "uuid"
    serializer_class = serializers.CallFormFlowSerializer
    queryset = proposal_models.Call.objects.all()
    permission_classes = (rf_permissions.IsAuthenticated,)

    def get_queryset(self):
        return filter_queryset_for_user(super().get_queryset(), self.request.user)

    def get_object(self):
        call = super().get_object()
        call.form_flow = serializers.get_call_form_flow(call)
        return call

    @extend_schema(responses=serializers.CallFormFlowSerializer)
    def retrieve(self, request, uuid=None):
        return response.Response(self.get_serializer(self.get_object()).data)

    @extend_schema(
        request=serializers.CallFormFlowSerializer,
        responses=serializers.CallFormFlowSerializer,
    )
    def update(self, request, uuid=None):
        call = self.get_object()
        permission_factory(PermissionEnum.UPDATE_CALL, CALL_PERMISSION_SOURCES)(
            request, self, call
        )
        serializer = self.get_serializer(call, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        logger.info(
            "Call %s form flow set to %s by %s.",
            call.uuid.hex,
            call.form_flow.key if call.form_flow else None,
            request.user.username,
        )
        return response.Response(serializer.data)


# --- applying ---------------------------------------------------------------------


class ProposalFormViewSet(viewsets.GenericViewSet):
    """A proposal's forms, by proposal UUID: their state, the answers, and
    links to fill them in."""

    lookup_field = "uuid"
    queryset = proposal_models.Proposal.objects.all()
    permission_classes = (rf_permissions.IsAuthenticated,)
    serializer_class = serializers.ProposalFormSerializer

    def get_queryset(self):
        return filter_queryset_for_user(
            super().get_queryset(), self.request.user
        ).select_related("round__call")

    def _state(self, proposal, flow):
        user = self.request.user
        available = client.is_available()
        answered = dict(
            proposal.form_step_responses.values_list("step_key", "modified")
        )
        open_keys = set(
            proposal.form_links.filter(state=models.FormLink.States.ISSUED).values_list(
                "step_key", flat=True
            )
        )
        step_keys = None
        if not form_permissions.sees_all_steps(user, proposal):
            step_keys = flows.reviewer_visible_keys(flow.steps)
        return {
            "proposal_uuid": proposal.uuid,
            "flow_key": flow.key,
            "flow_name": flow.name,
            "available": available,
            "can_fill_in": available and form_permissions.can_fill_in(user, proposal),
            "steps": [
                {
                    "key": step["key"],
                    "label": step["label"],
                    "completed": step["key"] in answered,
                    "submitted_at": answered.get(step["key"]),
                    "in_progress": step["key"] in open_keys,
                }
                for step in flow.steps
            ],
            "missing": responses.missing_steps(proposal, flow),
            "responses": responses.serialize_form_responses(
                proposal, flow.steps, step_keys
            ),
        }

    @extend_schema(
        responses=serializers.ProposalFormSerializer,
        description="The proposal's forms, which are answered, and the answers. "
        "Reviewers see only the forms the flow makes reviewer-visible.",
    )
    def retrieve(self, request, uuid=None):
        proposal = self.get_object()
        flow = _flow_for(proposal.round.call)
        return response.Response(
            serializers.ProposalFormSerializer(self._state(proposal, flow)).data
        )

    @extend_schema(
        request=serializers.ProposalFormLinkRequestSerializer,
        responses=serializers.ProposalFormLinkSerializer,
        description="A single-use link to fill in, resume or edit one of the "
        "proposal's forms. For the proposal's team, while it is a draft.",
    )
    @decorators.action(detail=True, methods=["post"])
    def link(self, request, uuid=None):
        proposal = self.get_object()
        if not client.is_available():
            raise exceptions.ValidationError(
                _("Forms are not available on this site just now.")
            )
        if not form_permissions.can_fill_in(request.user, proposal):
            raise exceptions.PermissionDenied(
                _(
                    "Only the proposal's team may fill in its forms, while it is a draft."
                )
            )
        flow = _flow_for(proposal.round.call)
        request_serializer = serializers.ProposalFormLinkRequestSerializer(
            data=request.data
        )
        request_serializer.is_valid(raise_exception=True)
        step = flows.get_step(flow.steps, request_serializer.validated_data["step"])
        if step is None:
            raise exceptions.ValidationError({"step": _("Not a form of this call.")})
        try:
            link = responses.issue_link(proposal, step, request.user)
        except responses.LinkError as e:
            raise exceptions.ValidationError(str(e))
        data = {
            "step_key": step["key"],
            "step_label": step["label"],
            "survey_url": link.url,
        }
        return response.Response(serializers.ProposalFormLinkSerializer(data).data)

    @extend_schema(
        request=None,
        responses=serializers.ProposalFormFetchResultSerializer,
        description="Bring the proposal's answers up to date from Formbricks, "
        "for when a response has not arrived on its own.",
    )
    @decorators.action(detail=True, methods=["post"])
    def fetch(self, request, uuid=None):
        proposal = self.get_object()
        flow = _flow_for(proposal.round.call)
        if not client.is_available():
            raise exceptions.ValidationError(
                _("Forms are not available on this site just now.")
            )
        try:
            outcomes = responses.fetch_for_proposal(proposal)
        except client.FormbricksError as e:
            logger.warning("Fetch for proposal %s failed: %s", proposal.uuid.hex, e)
            raise exceptions.ValidationError(
                _("Formbricks cannot be reached just now. Please try again later.")
            )
        data = self._state(proposal, flow)
        data["fetched"] = outcomes.get("applied", 0) + outcomes.get("updated", 0)
        return response.Response(
            serializers.ProposalFormFetchResultSerializer(data).data
        )


# --- the webhook --------------------------------------------------------------------


class ProposalFormWebhookView(views.APIView):
    """Formbricks' webhook: "responseFinished", and "responseUpdated" (a
    correction made in Formbricks, which is the source of truth).

    Signed by Formbricks (client.verify_signature). The response is matched
    to its proposal and form only by its single-use link id, which Waldur
    issued and recorded (responses.apply_response); nothing in the answers
    is trusted, since anyone can fill in a survey.
    """

    authentication_classes = ()
    permission_classes = (rf_permissions.AllowAny,)

    # Called by Formbricks, not the frontend: not in the schema or the SDK.
    @extend_schema(exclude=True)
    def post(self, request):
        # Formbricks' "Test endpoint" button posts {"event": "testEndpoint"},
        # signed with a secret it only reveals once the webhook is saved - so
        # it cannot verify here, and Formbricks fails the test on a 5xx. It
        # changes nothing, so it is acknowledged before anything is checked.
        # The raw body is read first: the signature is over it, and Django
        # only keeps it if it is read before the parsed data.
        request.body  # noqa: B018
        payload = request.data if isinstance(request.data, dict) else {}
        if payload.get("event") == "testEndpoint":
            logger.info("Formbricks webhook test received.")
            return response.Response({"detail": "ok"}, status=status.HTTP_200_OK)
        if not client.is_available():
            # Acknowledged, not refused: a 5xx would make Formbricks retry, and
            # would fail its test while the site is still being set up (the
            # connection cannot be enabled before the webhook's secret is known).
            logger.warning("Formbricks webhook ignored: Formbricks forms are off.")
            return response.Response(
                {"detail": "Ignored: Formbricks forms are off."},
                status=status.HTTP_200_OK,
            )
        if not client.verify_signature(request):
            raise exceptions.PermissionDenied(_("Invalid webhook signature."))

        if payload.get("event") not in ("responseFinished", "responseUpdated"):
            return response.Response(status=status.HTTP_200_OK)
        record = payload.get("data")
        if not isinstance(record, dict):
            return response.Response(status=status.HTTP_400_BAD_REQUEST)
        outcome = responses.apply_response(record)
        # Ignored responses are still acknowledged: resending them would not
        # change the answer, and the reason is logged.
        return response.Response({"detail": outcome}, status=status.HTTP_200_OK)
