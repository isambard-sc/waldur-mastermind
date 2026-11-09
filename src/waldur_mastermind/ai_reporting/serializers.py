import base64

from rest_framework import serializers

from waldur_mastermind.ai_reporting import models


class AskRequestSerializer(serializers.Serializer):
    prompt = serializers.CharField(allow_blank=False, trim_whitespace=True)
    # Targets a specific one of the caller's own sessions (e.g. one per open
    # browser tab) so its conversation can continue independently of any
    # other. Ownership is checked in the view, not here - this queryset only
    # confirms the uuid refers to *some* session. Omit to fall back to the
    # caller's most-recently-used session; combine with new_session to start
    # a fresh one instead.
    session = serializers.SlugRelatedField(
        slug_field="uuid",
        queryset=models.ReportingSession.objects.all(),
        required=False,
        allow_null=True,
        default=None,
    )
    new_session = serializers.BooleanField(default=False)


class ReportingFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ReportingFile
        fields = ["uuid", "name", "file"]
        read_only_fields = fields


class ReportingFileListSerializer(ReportingFileSerializer):
    """Used by ReportingFileViewSet's own list/retrieve action, where a file
    is returned on its own, not alongside the message that produced it.
    ReportingFileSerializer above is enough when a file is nested under its
    message (ReportingMessageSerializer.files) - there, the caller already
    has the question and session from the surrounding message object. Here,
    with no surrounding message to read that from, this serializer adds the
    question (`prompt`) and `session` directly onto the file itself, so a
    caller can still tell which conversation a file came from."""

    session = serializers.SlugRelatedField(
        source="message.session", slug_field="uuid", read_only=True
    )
    prompt = serializers.CharField(source="message.prompt", read_only=True)

    class Meta(ReportingFileSerializer.Meta):
        fields = [*ReportingFileSerializer.Meta.fields, "created", "session", "prompt"]
        read_only_fields = fields


class ReportingMessageSerializer(serializers.ModelSerializer):
    session = serializers.SlugRelatedField(slug_field="uuid", read_only=True)
    files = ReportingFileSerializer(many=True, read_only=True)

    class Meta:
        model = models.ReportingMessage
        fields = [
            "uuid",
            "session",
            "prompt",
            "answer",
            "status",
            "progress",
            "new_files",
            "files",
            "error_message",
            "created",
        ]
        read_only_fields = fields


class ReportingSessionSerializer(serializers.ModelSerializer):
    # Both annotated onto the queryset by ReportingSessionViewSet.get_queryset - not
    # real model fields, so plain read-only declarations here just describe their type
    # for the OpenAPI schema and serialize whatever the queryset already computed.
    last_activity = serializers.DateTimeField(read_only=True)
    message_count = serializers.IntegerField(read_only=True)
    first_prompt = serializers.SerializerMethodField()

    class Meta:
        model = models.ReportingSession
        fields = ["uuid", "created", "last_activity", "message_count", "first_prompt"]
        read_only_fields = fields

    def get_first_prompt(self, obj) -> str:
        """The conversation's own opening question, as a stable label for it in a
        history list - unlike the latest message, this doesn't change as the
        conversation grows. Reads the view's Prefetch(..., to_attr="ordered_messages")
        when present to avoid a query per row; falls back to a direct query otherwise
        (e.g. when this serializer is used outside that queryset, such as in a test)."""
        messages = getattr(obj, "ordered_messages", None)
        first = messages[0] if messages else obj.messages.order_by("created").first()
        return first.prompt if first else ""


class UsageStatsDailySerializer(serializers.Serializer):
    date = serializers.DateField()
    input_tokens = serializers.IntegerField()
    output_tokens = serializers.IntegerField()
    requests = serializers.IntegerField()


class UsageStatsByUserSerializer(serializers.Serializer):
    user = serializers.UUIDField()
    full_name = serializers.CharField()
    username = serializers.CharField()
    input_tokens = serializers.IntegerField()
    output_tokens = serializers.IntegerField()
    requests = serializers.IntegerField()


class UsageStatsResponseSerializer(serializers.Serializer):
    """See ReportingMessageViewSet.usage_stats - the one endpoint in this
    viewset that is deliberately NOT scoped to the caller's own messages, so
    staff/allocators can see actual site-wide AI reporting token consumption
    instead of just guessing at how expensive the feature is."""

    period_days = serializers.IntegerField()
    total_input_tokens = serializers.IntegerField()
    total_output_tokens = serializers.IntegerField()
    total_requests = serializers.IntegerField()
    daily = UsageStatsDailySerializer(many=True)
    by_user = UsageStatsByUserSerializer(many=True)


class HarnessConnectionSerializer(serializers.ModelSerializer):
    """The site's AI reporting harness connection - same shape as
    proposal_forms.serializers.FormbricksConnectionSerializer for the same
    kind of value.

    signing_private_key is write-only: leave it out of a PATCH to keep
    whatever is currently stored, or send an empty string to clear it
    (turning signing back off). signing_private_key_set says whether one is
    stored right now, without ever returning the key itself."""

    signing_private_key = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
        help_text="Base64-encoded raw Ed25519 private key bytes (see models.HarnessConnection).",
    )
    signing_private_key_set = serializers.SerializerMethodField()

    class Meta:
        model = models.HarnessConnection
        fields = (
            "base_url",
            "signing_private_key",
            "signing_private_key_set",
            "modified",
        )
        read_only_fields = ("modified",)

    def get_signing_private_key_set(self, connection) -> bool:
        return bool(connection.signing_private_key)

    def validate_signing_private_key(self, value):
        if not value:
            return value
        try:
            raw = base64.b64decode(value, validate=True)
        except Exception:
            raise serializers.ValidationError("Not valid base64.")
        if len(raw) != 32:
            raise serializers.ValidationError(
                "Not a raw Ed25519 private key: expected 32 bytes once base64-decoded."
            )
        return value
