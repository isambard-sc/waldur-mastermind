from django.db import transaction
from django.urls import reverse
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from waldur_core.core.models import is_feature_enabled
from waldur_mastermind.proposal import models as proposal_models

from . import client, flows, models

# --- connection -------------------------------------------------------------


class FormbricksConnectionSerializer(serializers.ModelSerializer):
    """The site's Formbricks server.

    The API key and webhook secret are write-only: leave one out to keep it,
    send an empty string to clear it. api_key_set and webhook_secret_set say
    whether one is stored.
    """

    api_key = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        help_text="Formbricks Management API key, with read access to the "
        "surveys and responses of the flows' environment.",
    )
    webhook_secret = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        help_text="Signing secret Formbricks shows for the webhook, e.g. 'whsec_...'.",
    )
    api_key_set = serializers.SerializerMethodField()
    webhook_secret_set = serializers.SerializerMethodField()
    is_configured = serializers.BooleanField(read_only=True)
    webhook_url = serializers.SerializerMethodField(
        help_text="The URL to give Formbricks as the webhook endpoint."
    )

    class Meta:
        model = models.FormbricksConnection
        fields = (
            "enabled",
            "base_url",
            "management_api_url",
            "api_key",
            "webhook_secret",
            "api_key_set",
            "webhook_secret_set",
            "is_configured",
            "webhook_url",
            "modified",
        )
        read_only_fields = ("modified",)

    def get_api_key_set(self, connection) -> bool:
        return bool(connection.api_key)

    def get_webhook_secret_set(self, connection) -> bool:
        return bool(connection.webhook_secret)

    def get_webhook_url(self, connection) -> str:
        path = reverse("proposal-form-webhook")
        request = self.context.get("request")
        return request.build_absolute_uri(path) if request else path

    def validate_webhook_secret(self, value):
        if value and client._signing_key(value) is None:
            raise serializers.ValidationError(
                "Not a Formbricks signing secret: expected 'whsec_' followed by base64."
            )
        return value

    def validate(self, attrs):
        merged = {
            field: attrs.get(field, getattr(self.instance, field))
            for field in ("enabled", "base_url", "api_key", "webhook_secret")
        }
        if merged["enabled"] and not all(
            merged[field] for field in ("base_url", "api_key", "webhook_secret")
        ):
            raise serializers.ValidationError(
                {
                    "enabled": "Set the URL, API key and webhook secret before "
                    "enabling Formbricks."
                }
            )
        return attrs


class FormbricksConnectionTestSerializer(serializers.Serializer):
    ok = serializers.BooleanField()
    detail = serializers.CharField()


# --- flows --------------------------------------------------------------------


class FormFlowStepSerializer(serializers.Serializer):
    key = serializers.SlugField(help_text="Stable id of the step, e.g. 'compliance'.")
    label = serializers.CharField(help_text="What applicants and reviewers see.")
    survey_id = serializers.CharField(help_text="The Formbricks survey id.")
    reviewer_visible = serializers.BooleanField(
        required=False, help_text="Whether reviewers may read this step's answers."
    )


@extend_schema_field(FormFlowStepSerializer(many=True))
class FormFlowStepsField(serializers.JSONField):
    """The steps as JSON, checked by flows.validate_steps rather than by
    nested serializers, so one set of rules serves the API, the import
    command and the webhook. Typed in the schema all the same."""


class FormFlowSerializer(serializers.HyperlinkedModelSerializer):
    steps = FormFlowStepsField()
    calls_count = serializers.SerializerMethodField()

    class Meta:
        model = models.FormFlow
        fields = (
            "url",
            "uuid",
            "key",
            "name",
            "description",
            "steps",
            "calls_count",
            "created",
            "modified",
        )
        read_only_fields = ("uuid", "created", "modified")
        extra_kwargs = {
            "url": {"lookup_field": "uuid", "view_name": "form-flow-detail"},
        }

    def get_calls_count(self, flow) -> int:
        return flow.call_links.count()

    def validate_steps(self, value):
        try:
            return flows.validate_steps(value)
        except flows.FlowError as e:
            raise serializers.ValidationError(str(e))

    def validate(self, attrs):
        flow = self.instance
        steps = attrs.get("steps")
        if flow is None or steps is None:
            return attrs
        # Answers already given are filed under their step key: dropping or
        # renaming a step would leave them orphaned.
        kept = {step["key"] for step in steps}
        answered = set(
            models.FormStepResponse.objects.filter(
                proposal__round__call__form_flow_link__flow=flow
            )
            .exclude(step_key__in=kept)
            .values_list("step_key", flat=True)
        )
        if answered:
            raise serializers.ValidationError(
                {
                    "steps": "Applicants have answered step(s) "
                    f"{', '.join(sorted(answered))}; they cannot be removed or "
                    "renamed."
                }
            )
        return attrs


class SurveyQuestionSerializer(serializers.Serializer):
    id = serializers.CharField()
    type = serializers.CharField()
    label = serializers.CharField(allow_blank=True)
    choices = serializers.ListField(child=serializers.CharField(allow_blank=True))


class FormFlowCheckStepSerializer(serializers.Serializer):
    key = serializers.CharField()
    survey_id = serializers.CharField()
    survey_name = serializers.CharField(allow_blank=True)
    in_sync = serializers.BooleanField(
        help_text="Nothing to change and nothing wrong: ready for applicants."
    )
    changes = serializers.ListField(
        child=serializers.CharField(),
        help_text="What Sync would change in the survey (after a sync: empty).",
    )
    problems = serializers.ListField(
        child=serializers.CharField(),
        help_text="What Waldur cannot fix itself, to be fixed in Formbricks.",
    )
    questions = SurveyQuestionSerializer(many=True)


class FormFlowCheckSerializer(serializers.Serializer):
    in_sync = serializers.BooleanField()
    steps = FormFlowCheckStepSerializer(many=True)


class FormbricksSurveySerializer(serializers.Serializer):
    """A survey in Formbricks, for choosing a flow's steps."""

    id = serializers.CharField()
    name = serializers.CharField(allow_blank=True)
    type = serializers.CharField(allow_blank=True)
    status = serializers.CharField(allow_blank=True)
    environment_id = serializers.CharField(allow_blank=True)
    question_count = serializers.IntegerField()
    updated_at = serializers.CharField(allow_blank=True)
    used_by_flows = serializers.ListField(
        child=serializers.CharField(),
        help_text="Keys of the flows that use this survey as a step.",
    )


# --- a call's flow ------------------------------------------------------------


class CallFormFlowSerializer(serializers.Serializer):
    """Which flow a call's applicants fill in; null for Waldur's own form."""

    call_uuid = serializers.UUIDField(source="uuid", read_only=True)
    flow = serializers.SlugRelatedField(
        slug_field="uuid",
        queryset=models.FormFlow.objects.all(),
        allow_null=True,
        source="form_flow",
    )
    flow_key = serializers.CharField(
        source="form_flow.key", read_only=True, allow_null=True
    )
    flow_name = serializers.CharField(
        source="form_flow.name", read_only=True, allow_null=True
    )
    locked = serializers.SerializerMethodField(
        help_text="True once the call has proposals: its flow can no longer change."
    )

    def get_locked(self, call) -> bool:
        return call_has_proposals(call)

    def validate(self, attrs):
        call = self.instance
        flow = attrs.get("form_flow")
        if flow != call.form_flow and call_has_proposals(call):
            raise serializers.ValidationError(
                "The call already has proposals, so its form can no longer change."
            )
        if flow is not None and not client.is_available():
            raise serializers.ValidationError(
                {
                    "flow": "Formbricks forms are not enabled on this site, so a "
                    "call cannot use a form flow."
                }
            )
        return attrs

    def update(self, call, validated_data):
        flow = validated_data["form_flow"]
        with transaction.atomic():
            if flow is None:
                models.CallFormFlow.objects.filter(call=call).delete()
            else:
                models.CallFormFlow.objects.update_or_create(
                    call=call, defaults={"flow": flow}
                )
        call.form_flow = flow
        return call


def call_has_proposals(call) -> bool:
    return proposal_models.Proposal.objects.filter(round__call=call).exists()


def get_call_form_flow(call):
    try:
        return call.form_flow_link.flow
    except models.CallFormFlow.DoesNotExist:
        return None


# --- applying -----------------------------------------------------------------


class ProposalFormLinkRequestSerializer(serializers.Serializer):
    step = serializers.CharField(help_text="Key of the form to open.")


class ProposalFormLinkSerializer(serializers.Serializer):
    step_key = serializers.CharField()
    step_label = serializers.CharField()
    survey_url = serializers.URLField(
        help_text="A single-use link to the form. Reopening it resumes a form "
        "left half-done; for an answered form it is prefilled to edit."
    )


class ProposalFormStepStatusSerializer(serializers.Serializer):
    key = serializers.CharField()
    label = serializers.CharField()
    completed = serializers.BooleanField()
    submitted_at = serializers.DateTimeField(allow_null=True)
    in_progress = serializers.BooleanField(
        help_text="A link to it was opened and its response has not arrived "
        "(still being filled in, or the webhook was missed: fetch)."
    )


class FormResponseQuestionSerializer(serializers.Serializer):
    question_id = serializers.CharField()
    label = serializers.CharField()
    answer = serializers.JSONField(
        help_text="As Formbricks sent it: text, a number, or a list for "
        "multiple choice."
    )


class FormStepResponseSerializer(serializers.Serializer):
    step_key = serializers.CharField()
    step_label = serializers.CharField()
    submitted_at = serializers.DateTimeField()
    questions = FormResponseQuestionSerializer(many=True)


class ProposalFormSerializer(serializers.Serializer):
    """A proposal's forms: which are answered, and the answers the viewer
    may read."""

    proposal_uuid = serializers.UUIDField()
    flow_key = serializers.CharField()
    flow_name = serializers.CharField()
    available = serializers.BooleanField(
        help_text="Whether Formbricks forms are on for this site now."
    )
    can_fill_in = serializers.BooleanField(
        help_text="Whether the viewer may open and edit the forms now: a member "
        "of the proposal's team, while it is a draft (including returned to "
        "the applicant), with forms available."
    )
    steps = ProposalFormStepStatusSerializer(many=True)
    missing = serializers.ListField(
        child=serializers.CharField(),
        help_text="Labels of the forms still to answer before submitting.",
    )
    responses = FormStepResponseSerializer(many=True)


class ProposalFormFetchResultSerializer(ProposalFormSerializer):
    fetched = serializers.IntegerField(
        help_text="How many responses this fetch brought in or updated."
    )


# --- fields added to upstream's call serializers ------------------------------


class CallFormFlowSummarySerializer(serializers.Serializer):
    uuid = serializers.UUIDField()
    key = serializers.CharField()
    name = serializers.CharField()


@extend_schema_field(CallFormFlowSummarySerializer(allow_null=True))
def _get_form_flow(serializer, call):
    # Null while the site has Formbricks forms switched off. Not while
    # Formbricks is merely unreachable or the connection paused: the call
    # still needs its forms answered before submission. Checked once per
    # response, not once per call in a list.
    context = serializer.context
    if "formbricks_forms_on" not in context:
        context["formbricks_forms_on"] = is_feature_enabled(client.FEATURE)
    if not context["formbricks_forms_on"]:
        return None
    flow = get_call_form_flow(call)
    if flow is None:
        return None
    return {"uuid": flow.uuid, "key": flow.key, "name": flow.name}


def add_form_flow_to_call(sender, fields, **kwargs):
    """Calls say whether they take applications through Formbricks, so the
    frontend knows which form to start."""
    fields["form_flow"] = serializers.SerializerMethodField(
        help_text="The Formbricks flow applicants fill in; null for Waldur's "
        "own proposal form."
    )
    setattr(sender, "get_form_flow", _get_form_flow)
