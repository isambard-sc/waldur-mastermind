import logging
import uuid as uuid_lib

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.shortcuts import redirect as http_redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import authentication as rf_authentication
from rest_framework import decorators, exceptions, response, status, views, viewsets
from rest_framework import permissions as rf_permissions

from waldur_core.core import utils as core_utils
from waldur_core.core.views import ActionsViewSet
from waldur_core.permissions import utils as permissions_utils
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.permissions.utils import permission_factory
from waldur_core.structure.managers import filter_queryset_for_user
from waldur_core.structure.permissions import is_staff
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal.enums import CallStates, ProposalStates, RoundStatuses
from waldur_mastermind.proposal.permissions import CALL_PERMISSION_SOURCES

from . import client, flows, mapper, models, serializers
from . import permissions as form_permissions

logger = logging.getLogger(__name__)
User = get_user_model()


def _api_url(request, name, **kwargs):
    return request.build_absolute_uri(reverse(name, kwargs=kwargs))


def _require_active():
    if not client.is_available():
        raise exceptions.ValidationError(
            _("Applying through Formbricks is not enabled on this site.")
        )


def _flow_for(call):
    flow = serializers.get_call_form_flow(call)
    if flow is None:
        raise exceptions.ValidationError(_("This call does not use a form flow."))
    return flow


def _survey_link(user, proposal, step):
    return {
        "step_key": step["key"],
        "step_label": step["label"],
        "survey_url": client.build_survey_url(
            step["survey_id"], client.hidden_fields(user, proposal)
        ),
    }


def _completion_url(proposal):
    return core_utils.format_homeport_link(
        "proposals/{proposal_uuid}/", proposal_uuid=proposal.uuid.hex
    )


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
                client.check_connection(connection)
                result = {"ok": True, "detail": "Connected."}
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

    @extend_schema(
        request=None,
        responses=serializers.FormFlowCheckSerializer,
        description="Check each step against its survey in Formbricks: that "
        "it exists, declares the hidden fields the flow needs, and has every "
        "question the step maps.",
    )
    @decorators.action(detail=True, methods=["post"], url_path="check")
    def check_surveys(self, request, uuid=None):
        flow = self.get_object()
        ending_base = _api_url(request, "proposal-form-redirect")
        results = []
        for step in flow.steps:
            problems = []
            try:
                survey = client.get_survey_definition(step["survey_id"])
            except client.FormbricksError as e:
                problems.append(str(e))
                survey = None
            if survey is not None:
                hidden = client.survey_hidden_fields(survey)
                missing = [f for f in client.REQUIRED_HIDDEN_FIELDS if f not in hidden]
                if missing:
                    problems.append(
                        "The survey does not declare hidden field(s) "
                        f"{', '.join(missing)}."
                    )
                questions = set(client.survey_labels(survey))
                expected = set(step.get("field_map", {}))
                if step.get("resources"):
                    expected.add(step["resources"]["question_id"])
                    for option in step["resources"]["options"]:
                        expected.update(option["attribute_map"])
                for question_id in sorted(expected - questions):
                    problems.append(f"The survey has no question {question_id}.")
            results.append(
                {
                    "key": step["key"],
                    "survey_id": step["survey_id"],
                    "ok": not problems,
                    "problems": problems,
                    "ending_url": client.redirect_ending_url(step["key"], ending_base),
                }
            )
        data = {"ok": all(r["ok"] for r in results), "steps": results}
        return response.Response(serializers.FormFlowCheckSerializer(data).data)

    # Not "check": check_permissions would shadow DRF's own method.
    check_surveys_permissions = [form_permissions.is_staff_or_support_for_reads]


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
    """An applicant's way through a call's form flow, by proposal UUID."""

    lookup_field = "uuid"
    queryset = proposal_models.Proposal.objects.all()
    permission_classes = (rf_permissions.IsAuthenticated,)
    serializer_class = serializers.ProposalFormSerializer

    def get_queryset(self):
        return filter_queryset_for_user(
            super().get_queryset(), self.request.user
        ).select_related("round__call")

    @extend_schema(
        request=serializers.ProposalFormStartSerializer,
        responses={201: serializers.ProposalFormStartResponseSerializer},
        description="Start an application: create a draft proposal in the "
        "round, with the caller as its manager, and return the first survey.",
    )
    @decorators.action(detail=False, methods=["post"])
    def start(self, request):
        _require_active()
        serializer = serializers.ProposalFormStartSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            call_round = proposal_models.Round.objects.select_related("call").get(
                uuid=serializer.validated_data["round_uuid"]
            )
        except proposal_models.Round.DoesNotExist:
            raise exceptions.ValidationError({"round_uuid": _("Round not found.")})
        call = call_round.call
        # The same rules as creating a proposal through the proposal API.
        if call.state != CallStates.ACTIVE:
            raise exceptions.ValidationError(_("Call is not active."))
        if call_round.status != RoundStatuses.OPEN:
            raise exceptions.ValidationError(
                _("The round is not open, so a proposal cannot be started.")
            )
        flow = _flow_for(call)
        permissions_utils.validate_user_restrictions(call, request.user)

        with transaction.atomic():
            proposal = proposal_models.Proposal.objects.create(
                # Replaced by the applicant's answer once the step that maps
                # the name is answered.
                name=f"Draft {uuid_lib.uuid4().hex[:8]}",
                round=call_round,
                created_by=request.user,
                state=ProposalStates.DRAFT,
            )
            proposal.add_user(
                request.user, ProposalRole.MANAGER, created_by=request.user
            )

        data = {
            "proposal_uuid": proposal.uuid,
            **_survey_link(request.user, proposal, flow.steps[0]),
        }
        return response.Response(
            serializers.ProposalFormStartResponseSerializer(data).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        responses=serializers.ProposalFormSerializer,
        description="Progress through the flow and the answers given. "
        "Reviewers see only the steps the flow makes reviewer-visible.",
    )
    def retrieve(self, request, uuid=None):
        proposal = self.get_object()
        flow = _flow_for(proposal.round.call)
        user = request.user

        answered = dict(
            proposal.form_step_responses.values_list("step_key", "modified")
        )
        can_fill_in = form_permissions.can_fill_in(user, proposal)
        next_step = None
        if can_fill_in and client.is_available():
            pending = [s for s in flow.steps if s["key"] not in answered]
            if pending:
                next_step = _survey_link(user, proposal, pending[0])

        step_keys = None
        if not form_permissions.sees_all_steps(user, proposal):
            step_keys = flows.reviewer_visible_keys(flow.steps)

        data = {
            "proposal_uuid": proposal.uuid,
            "flow_key": flow.key,
            "flow_name": flow.name,
            "can_fill_in": can_fill_in,
            "steps": [
                {
                    "key": step["key"],
                    "label": step["label"],
                    "completed": step["key"] in answered,
                    "submitted_at": answered.get(step["key"]),
                }
                for step in flow.steps
            ],
            "next_step": next_step,
            "responses": mapper.serialize_form_responses(
                proposal, flow.steps, step_keys
            ),
        }
        return response.Response(serializers.ProposalFormSerializer(data).data)

    @extend_schema(
        request=None,
        responses=serializers.ProposalFormSurveyLinkSerializer,
        parameters=[
            OpenApiParameter(
                "step",
                str,
                OpenApiParameter.QUERY,
                required=True,
                description="Key of the answered step to change.",
            )
        ],
        description="A survey link to change an answered step, prefilled "
        "with the answers Formbricks holds now.",
    )
    @decorators.action(detail=True, methods=["get"], url_path="edit-link")
    def edit_link(self, request, uuid=None):
        _require_active()
        proposal = self.get_object()
        if not form_permissions.can_fill_in(request.user, proposal):
            raise exceptions.PermissionDenied(
                _(
                    "Only the proposal's team may change its answers, while it is a draft."
                )
            )
        flow = _flow_for(proposal.round.call)
        step = flows.get_step(flow.steps, request.query_params.get("step", ""))
        if step is None:
            raise exceptions.ValidationError({"step": _("Not a step of this flow.")})
        stored = proposal.form_step_responses.filter(step_key=step["key"]).first()
        if stored is None:
            raise exceptions.ValidationError({"step": _("Not answered yet.")})
        try:
            answers = client.get_response(stored.response_id)
        except client.FormbricksError as e:
            logger.warning("Could not fetch Formbricks response for editing: %s", e)
            # The answers as last received are the next best thing.
            answers = stored.raw_response
        link = {
            "step_key": step["key"],
            "step_label": step["label"],
            "survey_url": client.build_survey_url(
                step["survey_id"],
                client.hidden_fields(request.user, proposal),
                prefill=client.prefill_from_answers(answers),
            ),
        }
        return response.Response(
            serializers.ProposalFormSurveyLinkSerializer(link).data
        )


# --- the survey ending's redirect ---------------------------------------------------


class RedirectTokenAuthentication(rf_authentication.BaseAuthentication):
    """Who is applying, from the redirect_token a survey carries.

    A survey's "Redirect to URL" ending is a plain browser navigation, with
    neither the frontend's token nor a session. Used only by the redirect
    view below: the token proves nothing anywhere else.
    """

    def authenticate(self, request):
        user_pk = client.verify_redirect_token(
            request.query_params.get("redirect_token"),
            request.query_params.get("proposal_uuid"),
        )
        if user_pk is None:
            raise exceptions.AuthenticationFailed(
                _(
                    "The link has expired or is not valid. Return to the portal to continue."
                )
            )
        try:
            return User.objects.get(pk=user_pk, is_active=True), None
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(_("The link is not valid."))


class ProposalFormRedirectView(views.APIView):
    """Where each survey's ending sends the applicant: on to the next
    unanswered step, or back to the proposal once all are answered."""

    authentication_classes = (RedirectTokenAuthentication,)
    permission_classes = (rf_permissions.IsAuthenticated,)

    # Not called by the frontend, so not in the API schema or the SDK.
    @extend_schema(exclude=True)
    def get(self, request):
        try:
            proposal = proposal_models.Proposal.objects.select_related(
                "round__call"
            ).get(uuid=request.query_params["proposal_uuid"])
        except (
            proposal_models.Proposal.DoesNotExist,
            KeyError,
            ValueError,
            DjangoValidationError,
        ):
            raise exceptions.NotFound()
        if not form_permissions.can_fill_in(request.user, proposal):
            return http_redirect(_completion_url(proposal))
        flow = serializers.get_call_form_flow(proposal.round.call)
        if flow is None or not client.is_available():
            return http_redirect(_completion_url(proposal))

        # The webhook for the step just finished may not have arrived yet,
        # so it counts as answered whatever the database says.
        current = request.query_params.get("step", "")
        answered = set(proposal.form_step_responses.values_list("step_key", flat=True))
        answered.add(current)
        keys = [s["key"] for s in flow.steps]
        start = keys.index(current) + 1 if current in keys else 0
        ordered = flow.steps[start:] + flow.steps[:start]
        pending = [s for s in ordered if s["key"] not in answered]
        if not pending:
            return http_redirect(_completion_url(proposal))
        return http_redirect(
            _survey_link(request.user, proposal, pending[0])["survey_url"]
        )


# --- the webhook --------------------------------------------------------------------


class ProposalFormWebhookView(views.APIView):
    """Formbricks' "responseFinished" webhook: keeps a step's answers and
    writes them onto the proposal.

    Signed by Formbricks (client.verify_signature). The answers carry the
    proposal and the applicant's redirect_token as hidden fields; the token
    must have been issued for that proposal to someone still on its team,
    and the proposal must still be a draft - a signature alone only proves
    the request came through Formbricks, where anyone can fill in a survey.
    """

    authentication_classes = ()
    permission_classes = (rf_permissions.AllowAny,)

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

        if payload.get("event") != "responseFinished":
            return response.Response(status=status.HTTP_200_OK)

        data = payload.get("data") or {}
        response_id = data.get("id")
        survey_id = data.get("surveyId")
        answers = data.get("data") or {}
        proposal_uuid = answers.get("proposal_uuid")
        if not (
            response_id and survey_id and isinstance(answers, dict) and proposal_uuid
        ):
            logger.warning(
                "Formbricks webhook ignored: no response id, survey id or proposal "
                "(response %s, survey %s).",
                response_id,
                survey_id,
            )
            return response.Response(status=status.HTTP_400_BAD_REQUEST)

        user_pk = client.verify_redirect_token(
            answers.get("redirect_token"), proposal_uuid
        )
        if user_pk is None:
            logger.warning(
                "Formbricks webhook refused: response %s has no valid token for "
                "proposal %s.",
                response_id,
                proposal_uuid,
            )
            return response.Response(status=status.HTTP_403_FORBIDDEN)

        try:
            proposal = proposal_models.Proposal.objects.select_related(
                "round__call"
            ).get(uuid=proposal_uuid)
        except (
            proposal_models.Proposal.DoesNotExist,
            ValueError,
            DjangoValidationError,
        ):
            return response.Response(status=status.HTTP_404_NOT_FOUND)

        user = User.objects.filter(pk=user_pk).first()
        if not form_permissions.can_fill_in(user, proposal):
            logger.warning(
                "Formbricks webhook refused: proposal %s is not a draft, or user "
                "%s is no longer on its team (response %s).",
                proposal.uuid.hex,
                user_pk,
                response_id,
            )
            return response.Response(status=status.HTTP_409_CONFLICT)

        flow = serializers.get_call_form_flow(proposal.round.call)
        step = flows.get_step_by_survey_id(flow.steps, survey_id) if flow else None
        if step is None:
            logger.warning(
                "Formbricks webhook refused: survey %s is not part of the flow "
                "of proposal %s's call.",
                survey_id,
                proposal.uuid.hex,
            )
            return response.Response(status=status.HTTP_404_NOT_FOUND)

        try:
            labels = client.get_survey(survey_id)
        except client.FormbricksError as e:
            # The answers matter more than their labels.
            logger.warning("Formbricks question labels not fetched: %s", e)
            labels = {}

        # The token is a credential: it is not kept.
        kept_answers = {k: v for k, v in answers.items() if k != "redirect_token"}
        try:
            with transaction.atomic():
                proposal = proposal_models.Proposal.objects.select_for_update().get(
                    pk=proposal.pk
                )
                if proposal.state != ProposalStates.DRAFT:
                    return response.Response(status=status.HTTP_409_CONFLICT)
                models.FormStepResponse.objects.update_or_create(
                    proposal=proposal,
                    step_key=step["key"],
                    defaults={
                        "survey_id": survey_id,
                        "response_id": response_id,
                        "raw_response": kept_answers,
                        "question_labels": labels,
                        "question_order": list(labels),
                    },
                )
                mapper.apply_step(proposal, answers, step)
        except mapper.FormbricksMappingError as e:
            logger.error(
                "Formbricks answers for proposal %s step %s not saved: %s",
                proposal.uuid.hex,
                step["key"],
                e,
            )
            return response.Response(
                {"detail": str(e)}, status=status.HTTP_422_UNPROCESSABLE_ENTITY
            )
        return response.Response(status=status.HTTP_200_OK)
