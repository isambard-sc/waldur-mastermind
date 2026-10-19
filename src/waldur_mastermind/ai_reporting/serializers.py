from rest_framework import serializers

from waldur_mastermind.ai_reporting import models


class AskRequestSerializer(serializers.Serializer):
    prompt = serializers.CharField(allow_blank=False, trim_whitespace=True)
    new_session = serializers.BooleanField(default=False)


class ReportingMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.ReportingMessage
        fields = [
            "uuid",
            "prompt",
            "answer",
            "status",
            "progress",
            "new_files",
            "error_message",
            "created",
        ]
        read_only_fields = fields
