import base64

from rest_framework import serializers

from waldur_mastermind.ai_reporting import models


class AskRequestSerializer(serializers.Serializer):
    prompt = serializers.CharField(allow_blank=False, trim_whitespace=True)
    # Ownership is checked in the view, not here. Omit to reuse the latest
    # session, or set new_session to start a fresh one.
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
    """For the standalone files list. Adds the question and session, since
    there's no surrounding message to read them from."""

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
    # Annotated by ReportingSessionViewSet.get_queryset.
    last_activity = serializers.DateTimeField(read_only=True)
    message_count = serializers.IntegerField(read_only=True)
    first_prompt = serializers.SerializerMethodField()

    class Meta:
        model = models.ReportingSession
        fields = ["uuid", "created", "last_activity", "message_count", "first_prompt"]
        read_only_fields = fields

    def get_first_prompt(self, obj) -> str:
        """The opening question, used as the conversation's label. Uses the
        view's prefetch when present, to avoid a query per row."""
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
    """Site-wide token usage, not scoped to the caller."""

    period_days = serializers.IntegerField()
    total_input_tokens = serializers.IntegerField()
    total_output_tokens = serializers.IntegerField()
    total_requests = serializers.IntegerField()
    daily = UsageStatsDailySerializer(many=True)
    by_user = UsageStatsByUserSerializer(many=True)


class HarnessConnectionSerializer(serializers.ModelSerializer):
    """signing_private_key is write-only: omit it to keep the stored key, or
    send an empty string to clear it. signing_private_key_set says whether
    one is stored."""

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
