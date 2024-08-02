import collections
import copy
import logging
import re

import pytz
from django.conf import settings as django_settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.reverse import reverse

from waldur_core.core import models as core_models
from waldur_core.core import serializers as core_serializers
from waldur_core.core import signals as core_signals
from waldur_core.core import utils as core_utils
from waldur_core.quotas.models import QuotaModelMixin, SharedQuotaMixin
from waldur_core.structure import models as structure_models
from waldur_core.structure import serializers as structure_serializers
from waldur_core.structure.permissions import _has_admin_access
from waldur_openstack.openstack import models as openstack_models
from waldur_openstack.openstack import serializers as openstack_serializers
from waldur_openstack.openstack.serializers import validate_private_cidr
from waldur_openstack.openstack_base.serializers import (
    BaseOpenStackServiceSerializer,
    BaseSecurityGroupRuleSerializer,
    BaseVolumeTypeSerializer,
)
from waldur_openstack.openstack_base.serializers import (
    FlavorSerializer as BaseFlavorSerializer,
)
from waldur_openstack.openstack_base.utils import volume_type_name_to_quota_name
from waldur_openstack.openstack_tenant.utils import get_valid_availability_zones

from . import models

logger = logging.getLogger(__name__)


class OpenStackTenantServiceSerializer(BaseOpenStackServiceSerializer):
    tenant_id = serializers.CharField(
        source="options.tenant_id",
        label=_("Tenant ID"),
        help_text=_("Tenant ID in OpenStack"),
    )

    external_network_id = serializers.CharField(
        source="options.external_network_id",
        help_text=_(
            "It is used to automatically assign floating IP to your virtual machine."
        ),
        label=_("Public/gateway network UUID"),
    )

    # Expose service settings quotas as service quotas as a temporary workaround.
    # It is needed in order to render quotas table in service provider details dialog.
    quotas = serializers.ReadOnlyField(source="settings.quotas")


class BaseAvailabilityZoneSerializer(structure_serializers.BasePropertySerializer):
    settings = serializers.HyperlinkedRelatedField(
        queryset=structure_models.ServiceSettings.objects.all(),
        view_name="servicesettings-detail",
        lookup_field="uuid",
        allow_null=True,
        required=False,
    )

    class Meta(structure_serializers.BasePropertySerializer.Meta):
        fields = ("url", "uuid", "name", "settings", "available")
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "settings": {"lookup_field": "uuid"},
        }


class ImageSerializer(structure_serializers.BasePropertySerializer):
    class Meta(structure_serializers.BasePropertySerializer.Meta):
        model = models.Image
        fields = (
            "url",
            "uuid",
            "name",
            "settings",
            "min_disk",
            "min_ram",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "settings": {"lookup_field": "uuid"},
        }


class FlavorSerializer(BaseFlavorSerializer):
    class Meta(BaseFlavorSerializer.Meta):
        model = models.Flavor
        extra_kwargs = copy.deepcopy(BaseFlavorSerializer.Meta.extra_kwargs)
        extra_kwargs["settings"]["queryset"] = (
            structure_models.ServiceSettings.objects.filter(type="OpenStackTenant")
        )


class UsageStatsSerializer(serializers.Serializer):
    shared = serializers.BooleanField()
    service_provider = serializers.ListField(child=serializers.CharField())


class NetworkSerializer(
    structure_serializers.FieldFilteringMixin,
    structure_serializers.BasePropertySerializer,
):
    class Meta(structure_serializers.BasePropertySerializer.Meta):
        model = models.Network
        fields = (
            "url",
            "uuid",
            "name",
            "type",
            "is_external",
            "segmentation_id",
            "subnets",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "settings": {"lookup_field": "uuid"},
            "subnets": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-subnet-detail",
            },
        }

    def get_filtered_field(self):
        return [
            ("segmentation_id", lambda user: user.is_staff or user.is_support),
        ]


class SubNetSerializer(structure_serializers.BasePropertySerializer):
    dns_nameservers = serializers.JSONField(read_only=True)
    allocation_pools = serializers.JSONField(read_only=True)
    network_name = serializers.ReadOnlyField(source="network.name")

    class Meta(structure_serializers.BasePropertySerializer.Meta):
        model = models.SubNet
        fields = (
            "url",
            "uuid",
            "name",
            "cidr",
            "gateway_ip",
            "allocation_pools",
            "ip_version",
            "enable_dhcp",
            "dns_nameservers",
            "network",
            "network_name",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "settings": {"lookup_field": "uuid"},
            "network": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-network-detail",
            },
        }


class FloatingIPSerializer(structure_serializers.BasePropertySerializer):
    class Meta(structure_serializers.BasePropertySerializer.Meta):
        model = models.FloatingIP
        fields = (
            "url",
            "uuid",
            "settings",
            "address",
            "runtime_state",
            "is_booked",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "settings": {"lookup_field": "uuid"},
        }


class SecurityGroupRuleSerializer(BaseSecurityGroupRuleSerializer):
    class Meta(BaseSecurityGroupRuleSerializer.Meta):
        model = models.SecurityGroupRule


class SecurityGroupSerializer(structure_serializers.BasePropertySerializer):
    rules = SecurityGroupRuleSerializer(many=True)

    class Meta(structure_serializers.BasePropertySerializer.Meta):
        model = models.SecurityGroup
        fields = ("url", "uuid", "name", "settings", "description", "rules")
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "settings": {"lookup_field": "uuid"},
        }


class ServerGroupSerializer(structure_serializers.BasePropertySerializer):
    class Meta(structure_serializers.BasePropertySerializer.Meta):
        model = models.ServerGroup
        fields = (
            "url",
            "uuid",
            "name",
            "policy",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "settings": {"lookup_field": "uuid"},
            "server-groups": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-server-group-detail",
            },
        }


class VolumeAvailabilityZoneSerializer(BaseAvailabilityZoneSerializer):
    class Meta(BaseAvailabilityZoneSerializer.Meta):
        model = models.VolumeAvailabilityZone


class VolumeSerializer(structure_serializers.BaseResourceSerializer):
    action_details = serializers.JSONField(read_only=True)
    metadata = serializers.JSONField(read_only=True)
    instance_name = serializers.SerializerMethodField()
    type_name = serializers.CharField(source="type.name", read_only=True)
    availability_zone_name = serializers.CharField(
        source="availability_zone.name", read_only=True
    )

    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        model = models.Volume
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "source_snapshot",
            "size",
            "bootable",
            "metadata",
            "image",
            "image_metadata",
            "image_name",
            "type",
            "type_name",
            "runtime_state",
            "availability_zone",
            "availability_zone_name",
            "device",
            "action",
            "action_details",
            "instance",
            "instance_name",
        )
        read_only_fields = (
            structure_serializers.BaseResourceSerializer.Meta.read_only_fields
            + (
                "image_metadata",
                "image_name",
                "source_snapshot",
                "runtime_state",
                "device",
                "metadata",
                "action",
                "instance",
            )
        )
        protected_fields = (
            structure_serializers.BaseResourceSerializer.Meta.protected_fields
            + (
                "size",
                "image",
                "type",
                "availability_zone",
            )
        )
        extra_kwargs = dict(
            instance={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-instance-detail",
            },
            image={"lookup_field": "uuid", "view_name": "openstacktenant-image-detail"},
            source_snapshot={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-snapshot-detail",
            },
            type={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-volume-type-detail",
            },
            availability_zone={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-volume-availability-zone-detail",
            },
            size={"required": False, "allow_null": True},
            **structure_serializers.BaseResourceSerializer.Meta.extra_kwargs,
        )

    def get_instance_name(self, volume):
        if volume.instance:
            return volume.instance.name

    def validate(self, attrs):
        attrs = super().validate(attrs)

        if self.instance is None:
            # image validation
            image = attrs.get("image")
            service_settings = attrs["service_settings"]
            if image and image.settings != service_settings:
                raise serializers.ValidationError(
                    {"image": _("Image must belong to the same service settings")}
                )
            # snapshot & size validation
            size = attrs.get("size")
            snapshot = attrs.get("snapshot")
            if not size and not snapshot:
                raise serializers.ValidationError(
                    _("Snapshot or size should be defined")
                )
            if size and snapshot:
                raise serializers.ValidationError(
                    _("It is impossible to define both snapshot and size")
                )
            # image & size validation
            size = size or snapshot.size
            if image and image.min_disk > size:
                raise serializers.ValidationError(
                    {
                        "size": _(
                            "Volume size should be equal or greater than %s for selected image"
                        )
                        % image.min_disk
                    }
                )
            # type validation
            type = attrs.get("type")
            if type and type.settings != service_settings:
                raise serializers.ValidationError(
                    {"type": _("Volume type must belong to the same service settings")}
                )

            availability_zone = attrs.get("availability_zone")
            if availability_zone and availability_zone.settings != service_settings:
                raise serializers.ValidationError(
                    _("Availability zone must belong to the same service settings.")
                )
            if availability_zone and not availability_zone.available:
                raise serializers.ValidationError(_("Zone is not available."))
            if (
                not availability_zone
                and django_settings.WALDUR_OPENSTACK_TENANT["REQUIRE_AVAILABILITY_ZONE"]
            ):
                if (
                    models.VolumeAvailabilityZone.objects.filter(
                        settings=service_settings
                    ).count()
                    > 0
                ):
                    raise serializers.ValidationError(
                        _("Availability zone is mandatory.")
                    )

        return attrs

    def create(self, validated_data):
        if not validated_data.get("size"):
            validated_data["size"] = validated_data["snapshot"].size
        if validated_data.get("image"):
            validated_data["image_name"] = validated_data["image"].name
        return super().create(validated_data)


class VolumeExtendSerializer(serializers.Serializer):
    disk_size = serializers.IntegerField(min_value=1, label="Disk size")

    def validate_disk_size(self, disk_size):
        if disk_size < self.instance.size + 1024:
            raise serializers.ValidationError(
                _("Disk size should be greater or equal to %s")
                % (self.instance.size + 1024)
            )
        return disk_size

    @transaction.atomic
    def update(self, instance: models.Volume, validated_data):
        new_size = validated_data["disk_size"]

        for quota_holder in instance.get_quota_scopes():
            if not quota_holder:
                continue
            quota_holder.add_quota_usage(
                "storage", new_size - instance.size, validate=True
            )
            if instance.type:
                key = volume_type_name_to_quota_name(instance.type.name)
                delta = (new_size - instance.size) / 1024
                quota_holder.add_quota_usage(key, delta, validate=True)

        instance.size = new_size
        instance.save(update_fields=["size"])
        return instance


class VolumeAttachSerializer(
    structure_serializers.PermissionFieldFilteringMixin,
    serializers.HyperlinkedModelSerializer,
):
    class Meta:
        model = models.Volume
        fields = ["instance"]
        extra_kwargs = dict(
            instance={
                "required": True,
                "allow_null": False,
                "view_name": "openstacktenant-instance-detail",
                "lookup_field": "uuid",
            }
        )

    def get_filtered_field_names(self):
        return ("instance",)

    def validate_instance(self, instance):
        States, RuntimeStates = models.Instance.States, models.Instance.RuntimeStates
        if instance.state != States.OK or instance.runtime_state not in (
            RuntimeStates.SHUTOFF,
            RuntimeStates.ACTIVE,
        ):
            raise serializers.ValidationError(
                _(
                    "Volume can be attached only to shutoff or active instance in OK state."
                )
            )
        volume = self.instance
        if (
            instance.service_settings != volume.service_settings
            or instance.project != volume.project
        ):
            raise serializers.ValidationError(
                _("Volume and instance should belong to the same service and project.")
            )
        if volume.availability_zone and instance.availability_zone:
            valid_zones = get_valid_availability_zones(volume)
            if (
                valid_zones
                and valid_zones.get(instance.availability_zone.name)
                != volume.availability_zone.name
            ):
                raise serializers.ValidationError(
                    _(
                        "Volume cannot be attached to virtual machine related to the other availability zone."
                    )
                )
        return instance


class VolumeRetypeSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.Volume
        fields = ["type"]

    type = serializers.HyperlinkedRelatedField(
        view_name="openstacktenant-volume-type-detail",
        queryset=models.VolumeType.objects.all(),
        lookup_field="uuid",
        allow_null=False,
        required=True,
    )

    def validate_type(self, type):
        volume = self.instance
        if type.settings != volume.service_settings:
            raise serializers.ValidationError(
                _("Volume and type should belong to the same service.")
            )
        if type == volume.type:
            raise serializers.ValidationError(_("Volume already has requested type."))
        return type

    @transaction.atomic
    def update(self, instance: models.Volume, validated_data):
        old_type = instance.type
        new_type = validated_data.get("type")

        for quota_holder in instance.get_quota_scopes():
            if not quota_holder:
                continue
            quota_holder.add_quota_usage(
                volume_type_name_to_quota_name(old_type.name),
                -1 * instance.size / 1024,
                validate=True,
            )
            quota_holder.add_quota_usage(
                volume_type_name_to_quota_name(new_type.name),
                instance.size / 1024,
                validate=True,
            )

        return super().update(instance, validated_data)


class SnapshotRestorationSerializer(
    core_serializers.AugmentedSerializerMixin, serializers.HyperlinkedModelSerializer
):
    name = serializers.CharField(write_only=True, help_text=_("New volume name."))
    description = serializers.CharField(
        required=False, help_text=_("New volume description.")
    )
    volume_state = serializers.ReadOnlyField(source="volume.get_state_display")

    class Meta:
        model = models.SnapshotRestoration
        fields = (
            "uuid",
            "created",
            "name",
            "description",
            "volume",
            "volume_name",
            "volume_state",
            "volume_runtime_state",
            "volume_size",
            "volume_device",
        )
        read_only_fields = ("uuid", "created", "volume")
        related_paths = {"volume": ("name", "state", "runtime_state", "size", "device")}
        extra_kwargs = dict(
            volume={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-volume-detail",
            },
        )

    @transaction.atomic
    def create(self, validated_data):
        snapshot = self.context["view"].get_object()
        validated_data["snapshot"] = snapshot
        description = (
            validated_data.pop("description", None)
            or "Restored from snapshot %s" % snapshot.name
        )

        volume = models.Volume(
            source_snapshot=snapshot,
            service_settings=snapshot.service_settings,
            project=snapshot.project,
            name=validated_data.pop("name"),
            description=description,
            size=snapshot.size,
        )

        if snapshot.source_volume:
            volume.type = snapshot.source_volume.type

        volume.save()
        volume.increase_backend_quotas_usage(validate=True)
        validated_data["volume"] = volume

        return super().create(validated_data)


class SnapshotSerializer(structure_serializers.BaseResourceActionSerializer):
    source_volume_name = serializers.ReadOnlyField(source="source_volume.name")
    action_details = serializers.JSONField(read_only=True)
    metadata = serializers.JSONField(required=False)
    restorations = SnapshotRestorationSerializer(many=True, read_only=True)
    snapshot_schedule_uuid = serializers.ReadOnlyField(source="snapshot_schedule.uuid")

    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        model = models.Snapshot
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "source_volume",
            "size",
            "metadata",
            "runtime_state",
            "source_volume_name",
            "action",
            "action_details",
            "restorations",
            "kept_until",
            "snapshot_schedule",
            "snapshot_schedule_uuid",
        )
        read_only_fields = (
            structure_serializers.BaseResourceSerializer.Meta.read_only_fields
            + (
                "size",
                "source_volume",
                "metadata",
                "runtime_state",
                "action",
                "snapshot_schedule",
                "service_settings",
                "project",
            )
        )
        extra_kwargs = dict(
            source_volume={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-volume-detail",
            },
            snapshot_schedule={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-snapshot-schedule-detail",
            },
            **structure_serializers.BaseResourceSerializer.Meta.extra_kwargs,
        )

    def validate(self, attrs):
        # Skip validation on update
        if self.instance:
            return attrs

        attrs["source_volume"] = source_volume = self.context["view"].get_object()
        attrs["service_settings"] = source_volume.service_settings
        attrs["project"] = source_volume.project
        attrs["size"] = source_volume.size
        return super().validate(attrs)


class NestedVolumeSerializer(
    core_serializers.AugmentedSerializerMixin,
    serializers.HyperlinkedModelSerializer,
    structure_serializers.BasicResourceSerializer,
):
    state = serializers.ReadOnlyField(source="get_state_display")
    type_name = serializers.CharField(source="type.name", read_only=True)

    class Meta:
        model = models.Volume
        fields = (
            "url",
            "uuid",
            "name",
            "image_name",
            "state",
            "bootable",
            "size",
            "device",
            "resource_type",
            "type",
            "type_name",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "type": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-volume-type-detail",
            },
        }


class NestedSecurityGroupRuleSerializer(BaseSecurityGroupRuleSerializer):
    class Meta(BaseSecurityGroupRuleSerializer.Meta):
        model = models.SecurityGroupRule
        fields = BaseSecurityGroupRuleSerializer.Meta.fields + ("id",)

    def to_internal_value(self, data):
        # Return exist security group as internal value if id is provided
        if "id" in data:
            try:
                return models.SecurityGroupRule.objects.get(id=data["id"])
            except models.SecurityGroup.DoesNotExist:
                raise serializers.ValidationError(
                    _("Security group with id %s does not exist") % data["id"]
                )
        else:
            internal_data = super().to_internal_value(data)
            return models.SecurityGroupRule(**internal_data)


class NestedSecurityGroupSerializer(
    core_serializers.AugmentedSerializerMixin,
    core_serializers.HyperlinkedRelatedModelSerializer,
):
    rules = NestedSecurityGroupRuleSerializer(
        many=True,
        read_only=True,
    )
    state = serializers.ReadOnlyField(source="get_state_display")

    class Meta:
        model = models.SecurityGroup
        fields = ("url", "name", "rules", "description", "state")
        read_only_fields = ("name", "rules", "description", "state")
        extra_kwargs = {"url": {"lookup_field": "uuid"}}


class NestedServerGroupSerializer(
    core_serializers.AugmentedSerializerMixin,
    core_serializers.HyperlinkedRelatedModelSerializer,
):
    state = serializers.ReadOnlyField(source="get_state_display")

    class Meta:
        model = models.ServerGroup
        fields = ("url", "name", "policy", "state")
        read_only_fields = ("name", "policy", "state")
        extra_kwargs = {"url": {"lookup_field": "uuid"}}


class NestedInternalIPSerializer(
    core_serializers.AugmentedSerializerMixin, serializers.HyperlinkedModelSerializer
):
    allowed_address_pairs = serializers.JSONField(read_only=True)
    fixed_ips = serializers.JSONField(read_only=True)

    class Meta:
        model = models.InternalIP
        fields = (
            "fixed_ips",
            "mac_address",
            "subnet",
            "subnet_uuid",
            "subnet_name",
            "subnet_description",
            "subnet_cidr",
            "allowed_address_pairs",
            "device_id",
            "device_owner",
        )
        read_only_fields = (
            "fixed_ips",
            "mac_address",
            "subnet_uuid",
            "subnet_name",
            "subnet_description",
            "subnet_cidr",
            "allowed_address_pairs",
            "device_id",
            "device_owner",
        )
        related_paths = {
            "subnet": ("uuid", "name", "description", "cidr"),
        }
        extra_kwargs = {
            "subnet": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-subnet-detail",
            },
        }

    def to_internal_value(self, data):
        internal_value = super().to_internal_value(data)
        return models.InternalIP(
            subnet=internal_value["subnet"], settings=internal_value["subnet"].settings
        )


class NestedFloatingIPSerializer(
    core_serializers.AugmentedSerializerMixin,
    core_serializers.HyperlinkedRelatedModelSerializer,
):
    subnet = serializers.HyperlinkedRelatedField(
        queryset=models.SubNet.objects.all(),
        source="internal_ip.subnet",
        view_name="openstacktenant-subnet-detail",
        lookup_field="uuid",
    )
    subnet_uuid = serializers.ReadOnlyField(source="internal_ip.subnet.uuid")
    subnet_name = serializers.ReadOnlyField(source="internal_ip.subnet.name")
    subnet_description = serializers.ReadOnlyField(
        source="internal_ip.subnet.description"
    )
    subnet_cidr = serializers.ReadOnlyField(source="internal_ip.subnet.cidr")
    internal_ip_fixed_ips = serializers.JSONField(
        source="internal_ip.fixed_ips", read_only=True
    )

    class Meta:
        model = models.FloatingIP
        fields = (
            "url",
            "uuid",
            "address",
            "internal_ip_fixed_ips",
            "internal_ip_mac_address",
            "subnet",
            "subnet_uuid",
            "subnet_name",
            "subnet_description",
            "subnet_cidr",
        )
        read_only_fields = (
            "address",
            "internal_ip_fixed_ips",
            "internal_ip_mac_address",
        )
        related_paths = {"internal_ip": ("fixed_ips", "mac_address")}
        extra_kwargs = {
            "url": {"lookup_field": "uuid", "view_name": "openstacktenant-fip-detail"},
        }

    def to_internal_value(self, data):
        """
        Return pair (floating_ip, subnet) as internal value.

        On floating IP creation user should specify what subnet should be used
        for connection and may specify what exactly floating IP should be used.
        If floating IP is not specified it will be represented as None.
        """
        floating_ip = None
        if "url" in data:
            # use HyperlinkedRelatedModelSerializer (parent of NestedFloatingIPSerializer)
            # method to convert "url" to FloatingIP object
            floating_ip = super().to_internal_value(data)

        # use HyperlinkedModelSerializer (parent of HyperlinkedRelatedModelSerializer)
        # to convert "subnet" to SubNet object
        internal_value = super(
            core_serializers.HyperlinkedRelatedModelSerializer, self
        ).to_internal_value(data)
        subnet = internal_value["internal_ip"]["subnet"]

        return floating_ip, subnet


def _validate_instance_internal_ips(internal_ips, settings):
    """- make sure that internal_ips belong to specified setting;
    - make sure that internal_ips does not connect to the same subnet twice;
    """
    if not internal_ips:
        return
    subnets = [internal_ip.subnet for internal_ip in internal_ips]
    for subnet in subnets:
        if subnet.settings != settings:
            message = (
                _("Subnet %s does not belong to the same service settings as instance.")
                % subnet
            )
            raise serializers.ValidationError({"internal_ips_set": message})
    pairs = [
        (internal_ip.subnet, internal_ip.backend_id) for internal_ip in internal_ips
    ]
    duplicates = [
        subnet for subnet, count in collections.Counter(pairs).items() if count > 1
    ]
    if duplicates:
        raise serializers.ValidationError(
            _("It is impossible to connect to subnet %s twice.") % duplicates[0][0]
        )


def _validate_instance_security_groups(security_groups, settings):
    """Make sure that security_group belong to specified setting."""
    for security_group in security_groups:
        if security_group.settings != settings:
            error = _(
                "Security group %s does not belong to the same service settings as instance."
            )
            raise serializers.ValidationError(
                {"security_groups": error % security_group.name}
            )


def _validate_instance_server_group(server_group, settings):
    """Make sure that server_group belong to specified setting."""

    if server_group and server_group.settings != settings:
        error = _(
            "Server group %s does not belong to the same service settings as instance."
        )
        raise serializers.ValidationError({"server_group": error % server_group.name})


def _validate_instance_floating_ips(
    floating_ips_with_subnets, settings, instance_subnets
):
    if floating_ips_with_subnets and "external_network_id" not in settings.options:
        raise serializers.ValidationError(
            gettext(
                "Please specify tenant external network to perform floating IP operations."
            )
        )

    for floating_ip, subnet in floating_ips_with_subnets:
        if not subnet.is_connected:
            message = gettext("SubNet %s is not connected to router.") % subnet
            raise serializers.ValidationError({"floating_ips": message})
        if subnet not in instance_subnets:
            message = gettext("SubNet %s is not connected to instance.") % subnet
            raise serializers.ValidationError({"floating_ips": message})
        if not floating_ip:
            continue
        if floating_ip.is_booked:
            message = gettext(
                "Floating IP %s is already booked for another instance creation"
            )
            raise serializers.ValidationError({"floating_ips": message % floating_ip})
        if floating_ip.settings != settings:
            message = gettext(
                "Floating IP %s does not belong to the same service settings as instance."
            )
            raise serializers.ValidationError({"floating_ips": message % floating_ip})

    subnets = [subnet for _, subnet in floating_ips_with_subnets]
    duplicates = [
        subnet for subnet, count in collections.Counter(subnets).items() if count > 1
    ]
    if duplicates:
        raise serializers.ValidationError(
            gettext("It is impossible to use subnet %s twice.") % duplicates[0]
        )


def _validate_instance_name(data, max_len=255):
    """Copy paste from https://github.com/openstack/neutron-lib/blob/master/neutron_lib/api/validators/dns.py#L23"""

    # allow data to be lowercase. Internally OpenStack allows more flexibility
    # with hostnames as sanitizing happens, but we are more strict and want to preserve name <-> hostname mapping
    # https://github.com/openstack/nova/blob/e80300ac20388890539a7f709e526a0a5ba8e63d/nova/utils.py#L388

    DNS_LABEL_REGEX = "^([a-zA-Z0-9-]{1,63})$"
    try:
        # A trailing period is allowed to indicate that a name is fully
        # qualified per RFC 1034 (page 7).
        trimmed = data[:-1] if data.endswith(".") else data
        if len(trimmed) > max_len:
            raise TypeError(
                _("'%(trimmed)s' exceeds the %(maxlen)s character FQDN " "limit")
                % {"trimmed": trimmed, "maxlen": max_len}
            )
        labels = trimmed.split(".")
        for label in labels:
            if not label:
                raise TypeError(_("Encountered an empty component"))
            if label.endswith("-") or label.startswith("-"):
                raise TypeError(
                    _("Name '%s' must not start or end with a hyphen") % label
                )
            if not re.match(DNS_LABEL_REGEX, label):
                raise TypeError(
                    _(
                        "Name '%s' must be 1-63 characters long, each of "
                        "which can only be alphanumeric or a hyphen"
                    )
                    % label
                )
        # RFC 1123 hints that a TLD can't be all numeric. last is a TLD if
        # it's an FQDN.
        if len(labels) > 1 and re.match("^[0-9]+$", labels[-1]):
            raise TypeError(_("TLD '%s' must not be all numeric") % labels[-1])
    except TypeError as e:
        msg = _("'%(data)s' not a valid PQDN or FQDN. Reason: %(reason)s") % {
            "data": data,
            "reason": e,
        }
        raise serializers.ValidationError({"name": msg})


def _connect_floating_ip_to_instance(floating_ip, subnet, instance):
    """Connect floating IP to instance via specified subnet.
    If floating IP is not defined - take exist free one or create a new one.
    """
    external_network_id = instance.service_settings.options.get("external_network_id")
    if not core_utils.is_uuid_like(external_network_id):
        raise serializers.ValidationError(
            gettext("Service provider does not have valid value of external_network_id")
        )

    if not floating_ip:
        kwargs = {
            "settings": instance.service_settings,
            "is_booked": False,
            "backend_network_id": external_network_id,
        }
        # TODO: figure out why internal_ip__isnull throws errors when added to kwargs
        floating_ip = (
            models.FloatingIP.objects.filter(internal_ip__isnull=True)
            .filter(**kwargs)
            .first()
        )
        if not floating_ip:
            floating_ip = models.FloatingIP(**kwargs)
            floating_ip.increase_backend_quotas_usage(validate=True)
    floating_ip.is_booked = True
    floating_ip.internal_ip = models.InternalIP.objects.filter(
        instance=instance, subnet=subnet
    ).first()
    floating_ip.save()
    return floating_ip


class InstanceAvailabilityZoneSerializer(BaseAvailabilityZoneSerializer):
    class Meta(BaseAvailabilityZoneSerializer.Meta):
        model = models.InstanceAvailabilityZone


class DataVolumeSerializer(serializers.Serializer):
    size = serializers.IntegerField()
    volume_type = serializers.HyperlinkedRelatedField(
        view_name="openstacktenant-volume-type-detail",
        queryset=models.VolumeType.objects.all(),
        lookup_field="uuid",
        allow_null=True,
        required=False,
    )


class InstanceSerializer(structure_serializers.VirtualMachineSerializer):
    flavor = serializers.HyperlinkedRelatedField(
        view_name="openstacktenant-flavor-detail",
        lookup_field="uuid",
        queryset=models.Flavor.objects.all().select_related("settings"),
        write_only=True,
    )

    image = serializers.HyperlinkedRelatedField(
        view_name="openstacktenant-image-detail",
        lookup_field="uuid",
        queryset=models.Image.objects.all().select_related("settings"),
        write_only=True,
    )

    security_groups = NestedSecurityGroupSerializer(
        queryset=models.SecurityGroup.objects.all(), many=True, required=False
    )
    server_group = NestedServerGroupSerializer(
        queryset=models.ServerGroup.objects.all(), required=False
    )
    internal_ips_set = NestedInternalIPSerializer(many=True, required=True)
    floating_ips = NestedFloatingIPSerializer(
        queryset=models.FloatingIP.objects.all().filter(internal_ip__isnull=True),
        many=True,
        required=False,
    )

    system_volume_size = serializers.IntegerField(min_value=1024, write_only=True)
    system_volume_type = serializers.HyperlinkedRelatedField(
        view_name="openstacktenant-volume-type-detail",
        queryset=models.VolumeType.objects.all(),
        lookup_field="uuid",
        allow_null=True,
        required=False,
        write_only=True,
    )
    data_volume_size = serializers.IntegerField(
        min_value=1024, required=False, write_only=True
    )
    data_volume_type = serializers.HyperlinkedRelatedField(
        view_name="openstacktenant-volume-type-detail",
        queryset=models.VolumeType.objects.all(),
        lookup_field="uuid",
        allow_null=True,
        required=False,
        write_only=True,
    )
    data_volumes = DataVolumeSerializer(many=True, required=False, write_only=True)
    volumes = NestedVolumeSerializer(many=True, required=False, read_only=True)
    action_details = serializers.JSONField(read_only=True)

    availability_zone_name = serializers.CharField(
        source="availability_zone.name", read_only=True
    )
    tenant_uuid = serializers.SerializerMethodField()

    class Meta(structure_serializers.VirtualMachineSerializer.Meta):
        model = models.Instance
        fields = structure_serializers.VirtualMachineSerializer.Meta.fields + (
            "image",
            "flavor",
            "flavor_disk",
            "flavor_name",
            "system_volume_size",
            "system_volume_type",
            "data_volume_size",
            "data_volume_type",
            "volumes",
            "data_volumes",
            "security_groups",
            "server_group",
            "internal_ips",
            "floating_ips",
            "internal_ips_set",
            "availability_zone",
            "availability_zone_name",
            "connect_directly_to_external_network",
            "runtime_state",
            "action",
            "action_details",
            "tenant_uuid",
            "hypervisor_hostname",
        )
        protected_fields = (
            structure_serializers.VirtualMachineSerializer.Meta.protected_fields
            + (
                "flavor",
                "image",
                "system_volume_size",
                "data_volume_size",
                "floating_ips",
                "security_groups",
                "server_group",
                "internal_ips_set",
                "availability_zone",
                "connect_directly_to_external_network",
            )
        )
        read_only_fields = (
            structure_serializers.VirtualMachineSerializer.Meta.read_only_fields
            + (
                "flavor_disk",
                "runtime_state",
                "flavor_name",
                "action",
                "hypervisor_hostname",
            )
        )
        extra_kwargs = dict(
            availability_zone={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-instance-availability-zone-detail",
            },
            **structure_serializers.VirtualMachineSerializer.Meta.extra_kwargs,
        )

    def get_fields(self):
        fields = super().get_fields()
        user = self.context["request"].user

        if not user.is_staff and not user.is_support:
            if "hypervisor_hostname" in fields:
                del fields["hypervisor_hostname"]

        return fields

    def get_tenant_uuid(self, instance):
        service_settings = instance.service_settings
        tenant = service_settings.scope
        if not tenant:
            return
        if not isinstance(tenant, openstack_models.Tenant):
            return
        try:
            request = self.context["request"]
            user = request.user
        except (KeyError, AttributeError):
            return
        if not _has_admin_access(user, tenant.project):
            return
        return tenant.uuid.hex

    @staticmethod
    def eager_load(queryset, request):
        queryset = structure_serializers.VirtualMachineSerializer.eager_load(
            queryset, request
        )
        return queryset.prefetch_related(
            "security_groups",
            "security_groups__rules",
            "volumes",
        )

    def validate_name(self, name):
        _validate_instance_name(name)
        return name

    def validate(self, attrs):
        attrs = super().validate(attrs)

        # skip validation on object update
        if self.instance is not None:
            return attrs

        service_settings = attrs["service_settings"]
        flavor = attrs["flavor"]
        image = attrs["image"]

        if any(
            [flavor.settings != service_settings, image.settings != service_settings]
        ):
            raise serializers.ValidationError(
                _(
                    "Flavor and image must belong to the same service settings as instance."
                )
            )

        if image.min_ram > flavor.ram:
            raise serializers.ValidationError(
                {
                    "flavor": _("RAM of flavor is not enough for selected image %s")
                    % image.min_ram
                }
            )

        if image.min_disk > attrs["system_volume_size"]:
            raise serializers.ValidationError(
                {
                    "system_volume_size": _(
                        "System volume size has to be greater than %s MiB"
                    )
                    % image.min_disk
                }
            )
        if (
            attrs.get("connect_directly_to_external_network", False)
            and "external_network_id" not in service_settings.options
        ):
            raise serializers.ValidationError(
                gettext(
                    "Please specify tenant external network to request direct connection to external network."
                )
            )

        internal_ips = attrs.get("internal_ips_set", [])
        if len(internal_ips) == 0:
            raise serializers.ValidationError(
                gettext("Please specify at least one network.")
            )

        _validate_instance_security_groups(
            attrs.get("security_groups", []), service_settings
        )
        _validate_instance_server_group(
            attrs.get("server_group", None), service_settings
        )
        _validate_instance_internal_ips(internal_ips, service_settings)
        subnets = [internal_ip.subnet for internal_ip in internal_ips]
        _validate_instance_floating_ips(
            attrs.get("floating_ips", []), service_settings, subnets
        )

        availability_zone = attrs.get("availability_zone")
        if availability_zone and availability_zone.settings != service_settings:
            raise serializers.ValidationError(
                _(
                    "Instance and availability zone must belong to the same service settings as instance."
                )
            )
        if availability_zone and not availability_zone.available:
            raise serializers.ValidationError(_("Zone is not available."))

        if (
            not availability_zone
            and django_settings.WALDUR_OPENSTACK_TENANT["REQUIRE_AVAILABILITY_ZONE"]
        ):
            if (
                models.InstanceAvailabilityZone.objects.filter(
                    settings=service_settings
                ).count()
                > 0
            ):
                raise serializers.ValidationError(_("Availability zone is mandatory."))

        self.validate_quotas(attrs)
        return attrs

    def validate_quotas(self, attrs):
        parts: list[SharedQuotaMixin] = []

        service_settings = attrs["service_settings"]
        flavor: models.Flavor = attrs["flavor"]
        system_volume_size = attrs["system_volume_size"]
        data_volume_size = attrs.get("data_volume_size", 0)
        data_volumes = attrs.get("data_volumes", [])

        instance = models.Instance(cores=flavor.cores, ram=flavor.ram)
        parts.append(instance)

        system_volume = models.Volume(
            size=system_volume_size,
            type=attrs.get("system_volume_type"),
        )
        parts.append(system_volume)

        if data_volume_size:
            data_volume = models.Volume(
                size=data_volume_size,
                type=attrs.get("data_volume_type"),
            )
            parts.append(data_volume)

        for volume in data_volumes:
            data_volume = models.Volume(
                size=volume["size"],
                type=volume.get("volume_type"),
            )
            parts.append(data_volume)

        quota_deltas = {}
        for part in parts:
            for quota, delta in part.get_quota_deltas().items():
                quota_deltas.setdefault(quota, 0)
                quota_deltas[quota] += delta

        scopes: list[QuotaModelMixin] = service_settings, service_settings.scope
        for scope in scopes:
            scope.validate_quota_change(quota_deltas)

    def _find_volume_availability_zone(self, instance):
        # Find volume AZ using instance AZ. It is assumed that user can't select arbitrary
        # combination of volume and instance AZ. Once instance AZ is selected,
        # volume AZ is taken from settings.

        volume_availability_zone = None
        valid_zones = get_valid_availability_zones(instance)
        if instance.availability_zone and valid_zones:
            volume_availability_zone_name = valid_zones.get(
                instance.availability_zone.name
            )
            if volume_availability_zone_name:
                try:
                    volume_availability_zone = (
                        models.VolumeAvailabilityZone.objects.get(
                            name=volume_availability_zone_name,
                            settings=instance.service_settings,
                            available=True,
                        )
                    )
                except models.VolumeAvailabilityZone.DoesNotExist:
                    pass
        return volume_availability_zone

    @transaction.atomic
    def create(self, validated_data):
        """Store flavor, ssh_key and image details into instance model.
        Create volumes and security groups for instance.
        """
        security_groups = validated_data.pop("security_groups", [])
        server_group = validated_data.get("server_group")
        internal_ips = validated_data.pop("internal_ips_set", [])
        floating_ips_with_subnets = validated_data.pop("floating_ips", [])
        service_settings = validated_data["service_settings"]
        project = validated_data["project"]
        ssh_key: core_models.SshPublicKey = validated_data.get("ssh_public_key")
        if ssh_key:
            # We want names to be human readable in backend.
            # OpenStack only allows latin letters, digits, dashes, underscores and spaces
            # as key names, thus we mangle the original name.
            safe_name = re.sub(r"[^-a-zA-Z0-9 _]+", "_", ssh_key.name)[:17]
            validated_data["key_name"] = f"{ssh_key.uuid.hex}-{safe_name}"
            validated_data["key_fingerprint"] = ssh_key.fingerprint_md5

        flavor = validated_data["flavor"]
        validated_data["flavor_name"] = flavor.name
        validated_data["cores"] = flavor.cores
        validated_data["ram"] = flavor.ram
        validated_data["flavor_disk"] = flavor.disk

        image = validated_data["image"]
        validated_data["image_name"] = image.name
        validated_data["min_disk"] = image.min_disk
        validated_data["min_ram"] = image.min_ram

        system_volume_size = validated_data["system_volume_size"]
        data_volume_size = validated_data.get("data_volume_size", 0)
        total_disk = data_volume_size + system_volume_size

        data_volumes = validated_data.get("data_volumes", [])
        if data_volumes:
            total_disk += sum(volume["size"] for volume in data_volumes)

        validated_data["disk"] = total_disk

        instance = super().create(validated_data)

        # security groups
        instance.security_groups.add(*security_groups)
        # server group
        instance.server_group = server_group
        # internal IPs
        for internal_ip in internal_ips:
            internal_ip.instance = instance
            internal_ip.save()
        # floating IPs
        for floating_ip, subnet in floating_ips_with_subnets:
            _connect_floating_ip_to_instance(floating_ip, subnet, instance)

        volume_availability_zone = self._find_volume_availability_zone(instance)

        # volumes
        volumes: list[models.Volume] = []
        system_volume = models.Volume.objects.create(
            name=f"{instance.name[:143]}-system",  # volume name cannot be longer than 150 symbols
            service_settings=service_settings,
            project=project,
            size=system_volume_size,
            image=image,
            image_name=image.name,
            bootable=True,
            availability_zone=volume_availability_zone,
            type=validated_data.get("system_volume_type"),
        )
        volumes.append(system_volume)

        if data_volume_size:
            data_volume = models.Volume.objects.create(
                name=f"{instance.name[:145]}-data",  # volume name cannot be longer than 150 symbols
                service_settings=service_settings,
                project=project,
                size=data_volume_size,
                availability_zone=volume_availability_zone,
                type=validated_data.get("data_volume_type"),
            )
            volumes.append(data_volume)

        for index, volume in enumerate(data_volumes):
            data_volume = models.Volume.objects.create(
                name=f"{instance.name[:140]}-data-{index + 2}",  # volume name cannot be longer than 150 symbols
                service_settings=service_settings,
                project=project,
                size=volume["size"],
                availability_zone=volume_availability_zone,
                type=volume.get("volume_type"),
            )
            volumes.append(data_volume)

        for volume in volumes:
            volume.increase_backend_quotas_usage(validate=True)

        instance.volumes.add(*volumes)
        return instance


class InstanceFlavorChangeSerializer(serializers.Serializer):
    flavor = serializers.HyperlinkedRelatedField(
        view_name="openstacktenant-flavor-detail",
        lookup_field="uuid",
        queryset=models.Flavor.objects.all(),
    )

    def validate_flavor(self, value):
        if value is not None:
            if value.name == self.instance.flavor_name:
                raise serializers.ValidationError(
                    _("New flavor is the same as current.")
                )

            if value.settings != self.instance.service_settings:
                raise serializers.ValidationError(
                    _("New flavor is not within the same service settings")
                )

        return value

    @transaction.atomic
    def update(self, instance, validated_data):
        flavor = validated_data.get("flavor")

        settings = instance.service_settings
        quota_holders = [settings]

        # Service settings has optional field for related tenant resource.
        # We should update tenant quotas if related tenant is defined.
        # Otherwise stale quotas would be used for quota validation during instance provisioning.
        # Note that all tenant quotas are injected to service settings when application is bootstrapped.
        if settings.scope:
            quota_holders.append(settings.scope)

        for quota_holder in quota_holders:
            quota_holder.add_quota_usage(
                "ram", flavor.ram - instance.ram, validate=True
            )
            quota_holder.add_quota_usage(
                "vcpu", flavor.cores - instance.cores, validate=True
            )

        instance.ram = flavor.ram
        instance.cores = flavor.cores
        instance.flavor_disk = flavor.disk
        instance.flavor_name = flavor.name
        instance.save(update_fields=["ram", "cores", "flavor_name", "flavor_disk"])
        return instance


class InstanceDeleteSerializer(serializers.Serializer):
    delete_volumes = serializers.BooleanField(default=True)
    release_floating_ips = serializers.BooleanField(
        label=_("Release floating IPs"), default=True
    )

    def validate(self, attrs):
        if (
            attrs["delete_volumes"]
            and models.Snapshot.objects.filter(
                source_volume__instance=self.instance
            ).exists()
        ):
            raise serializers.ValidationError(
                _("Cannot delete instance. One of its volumes has attached snapshot.")
            )
        return attrs


class InstanceSecurityGroupsUpdateSerializer(serializers.Serializer):
    security_groups = NestedSecurityGroupSerializer(
        queryset=models.SecurityGroup.objects.all(),
        many=True,
    )

    def validate_security_groups(self, security_groups):
        for security_group in security_groups:
            if security_group.settings != self.instance.service_settings:
                raise serializers.ValidationError(
                    _("Security group %s is not within the same service settings")
                    % security_group.name
                )

        return security_groups

    @transaction.atomic
    def update(self, instance, validated_data):
        security_groups = validated_data.pop("security_groups", None)
        if security_groups is not None:
            instance.security_groups.clear()
            instance.security_groups.add(*security_groups)

        return instance


class AllowedAddressPairSerializer(serializers.Serializer):
    ip_address = serializers.CharField(
        default="192.168.42.0/24",
        initial="192.168.42.0/24",
        write_only=True,
    )
    mac_address = serializers.CharField(required=False)

    def validate_ip_address(self, value):
        return validate_private_cidr(value)


class InstanceAllowedAddressPairsUpdateSerializer(serializers.Serializer):
    subnet = serializers.HyperlinkedRelatedField(
        queryset=models.SubNet.objects.all(),
        view_name="openstacktenant-subnet-detail",
        lookup_field="uuid",
        write_only=True,
    )

    allowed_address_pairs = AllowedAddressPairSerializer(many=True)

    @transaction.atomic
    def update(self, instance, validated_data):
        subnet = validated_data["subnet"]
        try:
            internal_ip = models.InternalIP.objects.get(
                instance=instance, subnet=subnet
            )
        except models.InternalIP.DoesNotExist:
            raise serializers.ValidationError(
                _('Instance is not connected to subnet "%s" yet.') % subnet
            )

        internal_ip.allowed_address_pairs = validated_data["allowed_address_pairs"]
        internal_ip.save(update_fields=["allowed_address_pairs"])
        return instance


class InstanceInternalIPsSetUpdateSerializer(serializers.Serializer):
    internal_ips_set = NestedInternalIPSerializer(many=True)

    def validate_internal_ips_set(self, internal_ips_set):
        _validate_instance_internal_ips(
            internal_ips_set, self.instance.service_settings
        )
        return internal_ips_set

    @transaction.atomic
    def update(self, instance, validated_data):
        internal_ips_set = validated_data["internal_ips_set"]
        new_subnets = [ip.subnet for ip in internal_ips_set]
        # delete stale IPs
        models.InternalIP.objects.filter(instance=instance).exclude(
            subnet__in=new_subnets
        ).delete()
        # create new IPs
        for internal_ip in internal_ips_set:
            match = models.InternalIP.objects.filter(
                instance=instance, subnet=internal_ip.subnet
            ).first()
            if not match:
                models.InternalIP.objects.create(
                    instance=instance,
                    subnet=internal_ip.subnet,
                    settings=internal_ip.subnet.settings,
                )

        return instance


class InstanceFloatingIPsUpdateSerializer(serializers.Serializer):
    floating_ips = NestedFloatingIPSerializer(
        queryset=models.FloatingIP.objects.all(), many=True, required=False
    )

    def get_fields(self):
        fields = super().get_fields()
        instance = self.instance
        if instance:
            queryset = models.FloatingIP.objects.all().filter(
                Q(internal_ip__isnull=True) | Q(internal_ip__instance=instance)
            )
            fields["floating_ips"] = NestedFloatingIPSerializer(
                queryset=queryset, many=True, required=False
            )
            fields["floating_ips"].view_name = "openstacktenant-fip-detail"
        return fields

    def validate(self, attrs):
        subnets = self.instance.subnets.all()
        _validate_instance_floating_ips(
            attrs["floating_ips"], self.instance.service_settings, subnets
        )
        return attrs

    def update(self, instance, validated_data):
        floating_ips_with_subnets = validated_data["floating_ips"]
        floating_ips_to_disconnect = list(self.instance.floating_ips)

        # Store both old and new floating IP addresses for action event logger
        new_floating_ips = [
            floating_ip
            for (floating_ip, subnet) in floating_ips_with_subnets
            if floating_ip
        ]
        instance._old_floating_ips = [
            floating_ip.address for floating_ip in floating_ips_to_disconnect
        ]
        instance._new_floating_ips = [
            floating_ip.address for floating_ip in new_floating_ips
        ]

        for floating_ip, subnet in floating_ips_with_subnets:
            if floating_ip in floating_ips_to_disconnect:
                floating_ips_to_disconnect.remove(floating_ip)
                continue
            _connect_floating_ip_to_instance(floating_ip, subnet, instance)
        for floating_ip in floating_ips_to_disconnect:
            floating_ip.internal_ip = None
            floating_ip.save()
        return instance


class BackupRestorationSerializer(serializers.HyperlinkedModelSerializer):
    name = serializers.CharField(
        required=False,
        help_text=_("New instance name. Leave blank to use source instance name."),
    )
    security_groups = NestedSecurityGroupSerializer(
        queryset=models.SecurityGroup.objects.all(), many=True, required=False
    )
    internal_ips_set = NestedInternalIPSerializer(many=True, required=False)
    floating_ips = NestedFloatingIPSerializer(
        queryset=models.FloatingIP.objects.all().filter(internal_ip__isnull=True),
        many=True,
        required=False,
    )

    class Meta:
        model = models.BackupRestoration
        fields = (
            "uuid",
            "instance",
            "created",
            "flavor",
            "name",
            "floating_ips",
            "security_groups",
            "internal_ips_set",
        )
        read_only_fields = ("url", "uuid", "instance", "created", "backup")
        extra_kwargs = dict(
            instance={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-instance-detail",
            },
            flavor={
                "lookup_field": "uuid",
                "view_name": "openstacktenant-flavor-detail",
                "allow_null": False,
                "required": True,
            },
        )

    def validate(self, attrs):
        flavor = attrs["flavor"]
        backup = self.context["view"].get_object()
        try:
            backup.instance.volumes.get(bootable=True)
        except ObjectDoesNotExist:
            raise serializers.ValidationError(
                _("OpenStack instance should have bootable volume.")
            )

        settings = backup.instance.service_settings

        if flavor.settings != settings:
            raise serializers.ValidationError(
                {"flavor": _("Flavor is not within services' settings.")}
            )

        _validate_instance_security_groups(attrs.get("security_groups", []), settings)

        internal_ips = attrs.get("internal_ips_set", [])
        _validate_instance_internal_ips(internal_ips, settings)

        subnets = [internal_ip.subnet for internal_ip in internal_ips]
        _validate_instance_floating_ips(
            attrs.get("floating_ips", []), settings, subnets
        )

        return attrs

    @transaction.atomic
    def update(self, backup_instance, validated_data):
        flavor = validated_data["flavor"]
        validated_data["backup"] = backup = backup_instance
        source_instance = backup.instance
        # instance that will be restored
        metadata = backup.metadata or {}
        instance = models.Instance.objects.create(
            name=validated_data.pop("name", None)
            or metadata.get("name", source_instance.name),
            description=metadata.get("description", ""),
            service_settings=backup.service_settings,
            project=backup.project,
            flavor_disk=flavor.disk,
            flavor_name=flavor.name,
            key_name=source_instance.key_name,
            key_fingerprint=source_instance.key_fingerprint,
            cores=flavor.cores,
            ram=flavor.ram,
            min_ram=metadata.get("min_ram", 0),
            min_disk=metadata.get("min_disk", 0),
            image_name=metadata.get("image_name", ""),
            user_data=metadata.get("user_data", ""),
            disk=sum([snapshot.size for snapshot in backup.snapshots.all()]),
        )

        instance.internal_ips_set.add(
            *validated_data.pop("internal_ips_set", []), bulk=False
        )
        instance.security_groups.add(*validated_data.pop("security_groups", []))

        for floating_ip, subnet in validated_data.pop("floating_ips", []):
            _connect_floating_ip_to_instance(floating_ip, subnet, instance)

        instance.increase_backend_quotas_usage(validate=True)
        validated_data["instance"] = instance
        backup_restoration = super().create(validated_data)
        # restoration for each instance volume from snapshot.
        for snapshot in backup.snapshots.all():
            volume = models.Volume(
                source_snapshot=snapshot,
                service_settings=snapshot.service_settings,
                project=snapshot.project,
                name=f"{instance.name[:143]}-volume",
                description="Restored from backup %s" % backup.uuid.hex,
                size=snapshot.size,
            )
            volume.save()
            volume.increase_backend_quotas_usage(validate=True)
            instance.volumes.add(volume)
        return backup_restoration


class BackupSerializer(structure_serializers.BaseResourceActionSerializer):
    metadata = serializers.JSONField(read_only=True)
    instance_name = serializers.ReadOnlyField(source="instance.name")
    instance_security_groups = NestedSecurityGroupSerializer(
        read_only=True, many=True, source="instance.security_groups"
    )
    instance_internal_ips_set = NestedInternalIPSerializer(
        read_only=True, many=True, source="instance.internal_ips_set"
    )
    instance_floating_ips = NestedFloatingIPSerializer(
        read_only=True, many=True, source="instance.floating_ips"
    )

    restorations = BackupRestorationSerializer(many=True, read_only=True)
    backup_schedule_uuid = serializers.ReadOnlyField(source="backup_schedule.uuid")

    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        model = models.Backup
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "kept_until",
            "metadata",
            "instance",
            "instance_name",
            "restorations",
            "backup_schedule",
            "backup_schedule_uuid",
            "instance_security_groups",
            "instance_internal_ips_set",
            "instance_floating_ips",
        )
        read_only_fields = (
            structure_serializers.BaseResourceSerializer.Meta.read_only_fields
            + (
                "instance",
                "backup_schedule",
                "service_settings",
                "project",
            )
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "instance": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-instance-detail",
            },
            "backup_schedule": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-backup-schedule-detail",
            },
        }

    def validate(self, attrs):
        # Skip validation on update
        if self.instance:
            return attrs

        attrs["instance"] = instance = self.context["view"].get_object()
        attrs["service_settings"] = instance.service_settings
        attrs["project"] = instance.project
        attrs["metadata"] = self.get_backup_metadata(instance)
        return super().validate(attrs)

    @transaction.atomic
    def create(self, validated_data):
        backup = super().create(validated_data)
        self.create_backup_snapshots(backup)
        return backup

    @staticmethod
    def get_backup_metadata(instance):
        return {
            "name": instance.name,
            "description": instance.description,
            "min_ram": instance.min_ram,
            "min_disk": instance.min_disk,
            "size": instance.size,
            "key_name": instance.key_name,
            "key_fingerprint": instance.key_fingerprint,
            "user_data": instance.user_data,
            "flavor_name": instance.flavor_name,
            "image_name": instance.image_name,
        }

    @staticmethod
    def create_backup_snapshots(backup):
        for volume in backup.instance.volumes.all():
            snapshot = models.Snapshot.objects.create(
                name=f"Part of backup: {backup.name[:60]} (volume: {volume.name[:60]})",
                service_settings=backup.service_settings,
                project=backup.project,
                size=volume.size,
                source_volume=volume,
                description=f"Part of backup {backup.name} (UUID: {backup.uuid.hex})",
            )
            snapshot.increase_backend_quotas_usage(validate=True)
            backup.snapshots.add(snapshot)


class BaseScheduleSerializer(structure_serializers.BaseResourceActionSerializer):
    timezone = serializers.ChoiceField(
        choices=[(t, t) for t in pytz.all_timezones],
        initial=timezone.get_current_timezone_name(),
        default=timezone.get_current_timezone_name(),
    )

    class Meta(structure_serializers.BaseResourceSerializer.Meta):
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            "retention_time",
            "timezone",
            "maximal_number_of_resources",
            "schedule",
            "is_active",
            "next_trigger_at",
        )
        read_only_fields = (
            structure_serializers.BaseResourceSerializer.Meta.read_only_fields
            + (
                "is_active",
                "next_trigger_at",
                "service_settings",
                "project",
            )
        )


class BackupScheduleSerializer(BaseScheduleSerializer):
    class Meta(BaseScheduleSerializer.Meta):
        model = models.BackupSchedule
        fields = BaseScheduleSerializer.Meta.fields + ("instance", "instance_name")
        read_only_fields = BaseScheduleSerializer.Meta.read_only_fields + (
            "backups",
            "instance",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "instance": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-instance-detail",
            },
        }
        related_paths = {
            "instance": ("name",),
        }

    def validate(self, attrs):
        # Skip validation on update
        if self.instance:
            return attrs

        instance = self.context["view"].get_object()
        if not instance.volumes.filter(bootable=True).exists():
            raise serializers.ValidationError(
                _("OpenStack instance should have bootable volume.")
            )
        attrs["instance"] = instance
        attrs["service_settings"] = instance.service_settings
        attrs["project"] = instance.project
        attrs["state"] = instance.States.OK
        return super().validate(attrs)


class SnapshotScheduleSerializer(BaseScheduleSerializer):
    class Meta(BaseScheduleSerializer.Meta):
        model = models.SnapshotSchedule
        fields = BaseScheduleSerializer.Meta.fields + (
            "source_volume",
            "source_volume_name",
        )
        read_only_fields = BaseScheduleSerializer.Meta.read_only_fields + (
            "snapshots",
            "source_volume",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "source_volume": {
                "lookup_field": "uuid",
                "view_name": "openstacktenant-volume-detail",
            },
        }
        related_paths = {
            "source_volume": ("name",),
        }

    def validate(self, attrs):
        # Skip validation on update
        if self.instance:
            return attrs

        volume = self.context["view"].get_object()
        attrs["source_volume"] = volume
        attrs["service_settings"] = volume.service_settings
        attrs["project"] = volume.project
        attrs["state"] = volume.States.OK
        return super().validate(attrs)


def get_instance(openstack_floating_ip):
    # cache openstack instance on openstack floating_ip instance
    if hasattr(openstack_floating_ip, "_instance"):
        return openstack_floating_ip._instance
    if not openstack_floating_ip.backend_id or not openstack_floating_ip.address:
        openstack_floating_ip._instance = None
        return
    try:
        floating_ip = models.FloatingIP.objects.exclude(internal_ip__isnull=True).get(
            backend_id=openstack_floating_ip.backend_id,
            address=openstack_floating_ip.address,
        )
    except models.FloatingIP.DoesNotExist:
        openstack_floating_ip._instance = None
    else:
        instance = getattr(floating_ip.internal_ip, "instance", None)
        openstack_floating_ip._instance = instance
        return instance


def get_instance_attr(openstack_floating_ip, name):
    instance = get_instance(openstack_floating_ip)
    return getattr(instance, name, None)


def get_instance_uuid(serializer, openstack_floating_ip):
    return get_instance_attr(openstack_floating_ip, "uuid")


def get_instance_name(serializer, openstack_floating_ip):
    return get_instance_attr(openstack_floating_ip, "name")


def get_instance_url(serializer, openstack_floating_ip):
    instance = get_instance(openstack_floating_ip)
    if instance:
        return reverse(
            "openstacktenant-instance-detail",
            kwargs={"uuid": instance.uuid.hex},
            request=serializer.context["request"],
        )


def add_instance_fields(sender, fields, **kwargs):
    fields["instance_uuid"] = serializers.SerializerMethodField()
    setattr(sender, "get_instance_uuid", get_instance_uuid)
    fields["instance_name"] = serializers.SerializerMethodField()
    setattr(sender, "get_instance_name", get_instance_name)
    fields["instance_url"] = serializers.SerializerMethodField()
    setattr(sender, "get_instance_url", get_instance_url)


core_signals.pre_serializer_fields.connect(
    add_instance_fields, sender=openstack_serializers.FloatingIPSerializer
)


class ConsoleLogSerializer(serializers.Serializer):
    length = serializers.IntegerField(required=False)


class VolumeTypeSerializer(BaseVolumeTypeSerializer):
    class Meta(BaseVolumeTypeSerializer.Meta):
        model = models.VolumeType
        fields = BaseVolumeTypeSerializer.Meta.fields + ("is_default",)


class SharedSettingsCustomerSerializer(serializers.Serializer):
    name = serializers.ReadOnlyField()
    uuid = serializers.ReadOnlyField()
    created = serializers.ReadOnlyField()
    abbreviation = serializers.ReadOnlyField()
    vm_count = serializers.ReadOnlyField()


class BackendInstanceSerializer(serializers.ModelSerializer):
    availability_zone = serializers.ReadOnlyField(source="availability_zone.name")
    state = serializers.ReadOnlyField(source="get_state_display")

    class Meta:
        model = models.Instance
        fields = (
            "name",
            "key_name",
            "start_time",
            "state",
            "runtime_state",
            "created",
            "backend_id",
            "availability_zone",
            "hypervisor_hostname",
        )


class BackendVolumesSerializer(serializers.ModelSerializer):
    availability_zone = serializers.ReadOnlyField(source="availability_zone.name")
    state = serializers.ReadOnlyField(source="get_state_display")
    type = serializers.ReadOnlyField(source="type.name")

    class Meta:
        model = models.Volume
        fields = (
            "name",
            "description",
            "size",
            "metadata",
            "backend_id",
            "type",
            "bootable",
            "runtime_state",
            "state",
            "availability_zone",
        )
