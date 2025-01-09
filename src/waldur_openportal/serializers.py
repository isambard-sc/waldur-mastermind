import logging

from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions as rf_exceptions
from rest_framework import serializers as rf_serializers

from waldur_core.core import serializers as core_serializers
from waldur_core.structure import serializers as structure_serializers

from waldur_core.structure.permissions import _has_admin_access

from . import models

logger = logging.getLogger(__name__)


class OpenPortalServiceSerializer(structure_serializers.ServiceOptionsSerializer):
    class Meta:
        secret_fields = ("instance_name")

    instance_name = rf_serializers.CharField(
        source="options.instance_name", label=_("Full path name for the OpenPortal Agent managing this instance")
    )


class AllocationSerializer(
    structure_serializers.BaseResourceSerializer,
    core_serializers.AugmentedSerializerMixin,
):
    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        model = models.Allocation
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "node_limit",
            "groupname",
            "node_usage",
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
        queryset=models.Association.objects.all(),
        view_name="openportal-allocation-detail",
        lookup_field="uuid",
    )

    class Meta:
        model = models.Association
        fields = (
            "uuid",
            "username",
            "groupname",
            "useridentifier",
            "allocation",
        )


class UserInfoSerializer(rf_serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.UserInfo
        fields = (
            "shortname",
            "user",
        )
        extra_kwargs = {
            "user": {
                "lookup_field": "uuid",
                "view_name": "user-detail",
            },
        }


class UserInfoModifySerializer(UserInfoSerializer):

    def validate(self, attrs):
        logger.info(f"Validating UserInfo {attrs}")
        return attrs

    def create(self, validated_data):
        logger.info(f"Creating UserInfo {validated_data}")
        raise NotImplementedError()

    def update(self, instance, validated_data):
        logger.info(f"Updating UserInfo {validated_data}")
        raise NotImplementedError()


class ProjectInfoSerializer(rf_serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.ProjectInfo
        fields = (
            "project",
            "shortname",
            "allowed_destinations",
        )
        extra_kwargs = {
            "project": {
                "lookup_field": "uuid",
                "view_name": "project-detail",
            },
        }


class ProjectInfoModifySerializer(ProjectInfoSerializer):

    def validate(self, attrs):
        logger.info(f"Validating ProjectInfo {attrs}")
        return attrs

    def create(self, validated_data):
        logger.info(f"Creating ProjectInfo {validated_data}")
        raise NotImplementedError()

    def update(self, instance, validated_data):
        logger.info(f"Updating ProjectInfo {validated_data}")
        raise NotImplementedError()
