from rest_framework import serializers

from waldur_mastermind.marketplace import models as marketplace_models
from waldur_openportal import models as openportal_models


class UsernameSerializer(serializers.ModelSerializer):
    class Meta:
        model = openportal_models.Association
        fields = ("useridentifier",)


class SetStateSerializer(serializers.Serializer):
    state = serializers.CharField(max_length=18)


class SetLimitsSerializer(serializers.Serializer):
    limits = serializers.JSONField()

    class Meta:
        model = marketplace_models.Resource
        fields = ("limits",)


class SetBackendIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = openportal_models.Allocation
        fields = ("backend_id",)
