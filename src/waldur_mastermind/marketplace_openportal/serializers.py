from rest_framework import serializers

from waldur_openportal import models as openportal_models


class SetStateSerializer(serializers.Serializer):
    state = serializers.CharField(max_length=18)


class SetBackendIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = openportal_models.Allocation
        fields = ("backend_id",)
