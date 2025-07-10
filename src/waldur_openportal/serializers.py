import logging

from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions as rf_exceptions
from rest_framework import serializers as rf_serializers

from waldur_core.core import serializers as core_serializers
from waldur_core.structure import serializers as structure_serializers
from waldur_core.structure import models as structure_models
from waldur_mastermind.marketplace import models as marketplace_models

from waldur_core.structure.permissions import _has_admin_access

from . import models

logger = logging.getLogger(__name__)


class OpenPortalServiceSerializer(structure_serializers.ServiceOptionsSerializer):
    class Meta:
        secret_fields = ("instance_name", "project_class")

    instance_name = rf_serializers.CharField(
        source="options.instance_name",
        label=_("Full path name for the OpenPortal Agent managing this instance"),
        default=None,
        required=False,
    )

    project_class = rf_serializers.CharField(
        source="options.project_class",
        label=_("Class for projects created on the remote OpenPortal instance"),
        default=None,
        required=False,
    )

    allocation_unit = rf_serializers.CharField(
        source="options.allocation_unit",
        label=_("Unit for allocation limits"),
        default="NHR",
        required=False,
    )

    default_allocation = rf_serializers.FloatField(
        source="options.default_allocation",
        label=_("Default allocation for new projects on this resource"),
        default=None,
        required=False,
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


class RemoteAllocationSerializer(
    structure_serializers.BaseResourceSerializer,
    core_serializers.AugmentedSerializerMixin,
):
    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        model = models.RemoteAllocation
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "node_limit",
            "remote_project_identifier",
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
            url={
                "lookup_field": "uuid",
                "view_name": "openportal-remote-allocation-detail",
            },
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
        fields = "node_limit"


class RemoteAllocationSetLimitsSerializer(rf_serializers.ModelSerializer):
    node_limit = rf_serializers.IntegerField(min_value=-1)

    class Meta:
        model = models.RemoteAllocation
        fields = "node_limit"


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


class RemoteAllocationUserUsageCreateSerializer(
    rf_serializers.HyperlinkedModelSerializer
):
    class Meta:
        model = models.RemoteAllocationUserUsage
        fields = (
            "node_usage",
            "user",
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


class RemoteAllocationUserUsageSerializer(rf_serializers.HyperlinkedModelSerializer):
    full_name = rf_serializers.ReadOnlyField(source="user.full_name")

    class Meta:
        model = models.RemoteAllocationUserUsage
        fields = (
            "node_usage",
            "month",
            "year",
            "allocation",
            "user",
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


class RemoteAssociationSerializer(rf_serializers.HyperlinkedModelSerializer):
    allocation = rf_serializers.HyperlinkedRelatedField(
        queryset=models.RemoteAssociation.objects.all(),
        view_name="openportal-remote-allocation-detail",
        lookup_field="uuid",
    )

    class Meta:
        model = models.RemoteAssociation
        fields = (
            "uuid",
            "allocation",
        )


class HistoricalAllocationSerializer(rf_serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.HistoricalAllocation
        fields = ("node_usage", "month", "year", "allocation", "is_complete")
        extra_kwargs = {
            "allocation": {
                "lookup_field": "uuid",
                "view_name": "openportal-allocation-detail",
            },
        }


class HistoricalRemoteAllocationSerializer(rf_serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.HistoricalRemoteAllocation
        fields = ("node_usage", "month", "year", "allocation", "is_complete")
        extra_kwargs = {
            "allocation": {
                "lookup_field": "uuid",
                "view_name": "openportal-allocation-detail",
            },
        }


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


class ProjectClassSerializer(
    structure_serializers.PermissionFieldFilteringMixin,
    rf_serializers.ModelSerializer,
):
    customer = rf_serializers.HyperlinkedRelatedField(
        queryset=structure_models.Customer.objects.all(),
        view_name="customer-detail",
        lookup_field="uuid",
    )

    # offerings = rf_serializers.HyperlinkedRelatedField(
    #    many=True,
    #    queryset=marketplace_models.Offering.objects.all(),
    #    view_name="offering-detail",
    #    lookup_field="uuid",
    # )

    class Meta:
        model = models.ProjectClass
        fields = (
            "uuid",
            "name",
            "portal",
            "customer",
            "shortname",
            #        "offerings",
            "approval_limit",
            "max_credit_limit",
            "role_mapping",
        )

        related_paths = ("customer", "offerings")

    def get_filtered_field_names(self):
        return ("customer", "offerings")


class ManagedProjectSerializer(
    structure_serializers.PermissionFieldFilteringMixin,
    rf_serializers.ModelSerializer,
):
    state = rf_serializers.ReadOnlyField(source="get_state_display")

    reviewed_by_full_name = rf_serializers.CharField(
        read_only=True, source="reviewed_by.full_name"
    )
    reviewed_by_uuid = rf_serializers.UUIDField(
        read_only=True, source="reviewed_by.uuid"
    )

    project = rf_serializers.HyperlinkedRelatedField(
        queryset=structure_models.Project.objects.all(),
        view_name="project-detail",
        lookup_field="uuid",
    )

    details = rf_serializers.JSONField(
        read_only=True,
        help_text=_("Details of the project as provided by the remote OpenPortal."),
    )

    # project_class = rf_serializers.HyperlinkedRelatedField(
    #    queryset=models.ProjectClass.objects.all(),
    #    view_name="openportal-project-class",
    #    lookup_field="uuid",
    # )

    class Meta:
        model = models.ManagedProject

        fields = (
            "state",
            "created",
            "reviewed_at",
            "reviewed_by_full_name",
            "reviewed_by_uuid",
            "review_comment",
            "identifier",
            "details",
            "project",
            "project_class",
            "local_identifier",
        )

        related_paths = ("project",)

    def get_filtered_field_names(self):
        return ("project",)
