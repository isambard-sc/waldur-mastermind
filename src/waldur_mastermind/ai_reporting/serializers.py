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
