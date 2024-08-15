from rest_framework import serializers

from waldur_openportal import models as openportal_models


class UsernameSerializer(serializers.ModelSerializer):
    class Meta:
        model = openportal_models.Association
        fields = ("username",)


class SetStateSerializer(serializers.Serializer):
    state = serializers.CharField(max_length=18)


class SetBackendIdSerializer(serializers.ModelSerializer):
    class Meta:
        model = openportal_models.Allocation
        fields = ("backend_id",)
