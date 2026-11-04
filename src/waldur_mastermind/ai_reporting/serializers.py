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
