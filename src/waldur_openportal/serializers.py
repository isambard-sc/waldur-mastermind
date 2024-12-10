import re

from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions as rf_exceptions
from rest_framework import serializers as rf_serializers

from waldur_core.core import serializers as core_serializers
from waldur_core.structure import serializers as structure_serializers
from waldur_core.structure.permissions import _has_admin_access

from . import models


class OpenPortalServiceSerializer(structure_serializers.ServiceOptionsSerializer):
    class Meta:
        secret_fields = ("instance_name")

    instance_name = rf_serializers.CharField(
        source="options.instance_name", label=_("Full path name for the OpenPortal Agent managing this instance")
    )


class JobSerializer(structure_serializers.BaseResourceSerializer):
    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        model = models.Job
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "runtime_state",
            "command",
            "user",
            "user_uuid",
            "user_name",
            "report",
        )
        read_only_fields = structure_serializers.BaseResourceSerializer.Meta.read_only_fields + (
            "user",
            "report",
        )
        protected_fields = structure_serializers.BaseResourceSerializer.Meta.protected_fields + ("command",)
        extra_kwargs = {
            **structure_serializers.BaseResourceSerializer.Meta.extra_kwargs,
            "user": {"lookup_field": "uuid", "view_name": "user-detail"},
        }
        related_paths = {
            "user": ("uuid", "name"),
        }

    def get_fields(self):
        fields = super().get_fields()
        if not self.instance:
            fields["command"].required = True
            fields["command"].allow_null = False
        return fields

    def create(self, validated_data):
        validated_data["user"] = self.context["request"].user
        return super().create(validated_data)


class AllocationSerializer(
    structure_serializers.BaseResourceSerializer,
    core_serializers.AugmentedSerializerMixin,
):
    username = rf_serializers.SerializerMethodField()

    def get_username(self, allocation):
        request = self.context["request"]
        try:
            association = models.Association.objects.get(user=request.user)
            return association.username
        except models.Association.DoesNotExist:
            return None

    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        model = models.Allocation
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "node_limit",
            "node_usage",
            "username",
            "is_active",
        )
        read_only_fields = (
            structure_serializers.BaseResourceSerializer.Meta.read_only_fields
            + (
                "node_usage",
                "is_active",
            )
        )
        extra_kwargs = dict(
            url={"lookup_field": "uuid", "view_name": "openportal-allocation-detail"},
            node_limit={"validators": [MinValueValidator(0)]},
        )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        # Skip validation on update
        if self.instance:
            return attrs

        project = attrs["project"]
        user = self.context["request"].user
        if not _has_admin_access(user, project):
            raise rf_exceptions.PermissionDenied(
                _("You do not have permissions to create allocation for given project.")
            )
        return attrs


class AllocationSetLimitsSerializer(rf_serializers.ModelSerializer):
    node_limit = rf_serializers.IntegerField(min_value=-1)

    class Meta:
        model = models.Allocation
        fields = ("node_limit")


class AllocationUserUsageCreateSerializer(rf_serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.AllocationUserUsage
        fields = (
            "node_usage",
            "user",
            "username",
        )
        extra_kwargs = {
            "user": {
                "lookup_field": "uuid",
                "view_name": "user-detail",
            },
        }


class AllocationUserUsageSerializer(rf_serializers.HyperlinkedModelSerializer):
    full_name = rf_serializers.ReadOnlyField(source="user.full_name")

    class Meta:
        model = models.AllocationUserUsage
        fields = (
            "node_usage",
            "month",
            "year",
            "allocation",
            "user",
            "username",
            "full_name",
        )
        extra_kwargs = {
            "allocation": {
                "lookup_field": "uuid",
                "view_name": "openportal-allocation-detail",
            },
            "user": {
                "lookup_field": "uuid",
                "view_name": "user-detail",
            },
        }


class AssociationSerializer(rf_serializers.HyperlinkedModelSerializer):
    allocation = rf_serializers.HyperlinkedRelatedField(
        queryset=models.Allocation.objects.all(),
        view_name="openportal-allocation-detail",
        lookup_field="uuid",
    )

    class Meta:
        model = models.Association
        fields = (
            "uuid",
            "username",
            "allocation",
        )
