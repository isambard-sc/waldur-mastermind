import hashlib
import string

from django.db import transaction
from django.utils.crypto import get_random_string
from rest_framework import serializers

from waldur_core.core import serializers as core_serializers
from waldur_core.core import utils as core_utils
from waldur_core.core.models import SshPublicKey
from waldur_core.structure import serializers as structure_serializers

from . import models


def hash_string(value, length=16):
    return hashlib.sha256(value).hexdigest()[:length]


def generate_username():
    return 'user{}'.format(core_utils.pwgen(4))


def generate_password():
    lowercase = get_random_string(5, string.ascii_lowercase)
    uppercase = get_random_string(5, string.ascii_uppercase)
    digits = get_random_string(5, string.digits)
    return lowercase + uppercase + digits


class ServiceSerializer(core_serializers.ExtraFieldOptionsMixin,
                        structure_serializers.BaseServiceSerializer):

    SERVICE_ACCOUNT_EXTRA_FIELDS = {
        'tenant_id': 'Azure Active Directory tenant id or domain',
        'client_id': 'Azure Active Directory Application Client ID',
        'client_secret': 'Azure Active Directory Application Secret',
        'subscription_id': 'Azure Subscription Id',
    }

    class Meta(structure_serializers.BaseServiceSerializer.Meta):
        model = models.AzureService
        view_name = 'azure-detail'


class ImageSerializer(structure_serializers.BasePropertySerializer):

    class Meta(object):
        model = models.Image
        view_name = 'azure-image-detail'
        fields = ('url', 'uuid', 'publisher', 'name', 'sku', 'version')
        extra_kwargs = {
            'url': {'lookup_field': 'uuid'},
        }


class SizeSerializer(structure_serializers.BasePropertySerializer):

    class Meta(object):
        model = models.Size
        view_name = 'azure-size-detail'
        fields = ('url', 'uuid', 'name', 'max_data_disk_count',
                  'memory_in_mb', 'number_of_cores', 'os_disk_size_in_mb', 'resource_disk_size_in_mb')
        extra_kwargs = {
            'url': {'lookup_field': 'uuid'},
        }


class LocationSerializer(structure_serializers.BasePropertySerializer):

    class Meta(object):
        model = models.Location
        view_name = 'azure-location-detail'
        fields = ('url', 'uuid', 'name', 'latitude', 'longitude')
        extra_kwargs = {
            'url': {'lookup_field': 'uuid'},
        }


class ResourceGroupSerializer(structure_serializers.BaseResourceSerializer):
    service = serializers.HyperlinkedRelatedField(
        source='service_project_link.service',
        view_name='azure-detail',
        lookup_field='uuid',
        queryset=models.AzureService.objects.all(),
    )

    service_project_link = serializers.HyperlinkedRelatedField(
        view_name='azure-spl-detail',
        queryset=models.AzureServiceProjectLink.objects.all(),
    )

    location = serializers.HyperlinkedRelatedField(
        view_name='azure-location-detail',
        lookup_field='uuid',
        queryset=models.Location.objects.all(),
    )

    class Meta(object):
        model = models.ResourceGroup
        view_name = 'azure-resource-group-detail'
        fields = ('url', 'uuid', 'name', 'location')
        extra_kwargs = {
            'url': {'lookup_field': 'uuid'},
        }


class ServiceProjectLinkSerializer(structure_serializers.BaseServiceProjectLinkSerializer):

    class Meta(structure_serializers.BaseServiceProjectLinkSerializer.Meta):
        model = models.AzureServiceProjectLink
        view_name = 'azure-spl-detail'
        extra_kwargs = {
            'service': {'lookup_field': 'uuid', 'view_name': 'azure-detail'},
        }


class VirtualMachineSerializer(structure_serializers.VirtualMachineSerializer):

    service = serializers.HyperlinkedRelatedField(
        source='service_project_link.service',
        view_name='azure-detail',
        read_only=True,
        lookup_field='uuid')

    service_project_link = serializers.HyperlinkedRelatedField(
        view_name='azure-spl-detail',
        queryset=models.AzureServiceProjectLink.objects.all(),
        allow_null=True,
        required=False,
    )

    image = serializers.HyperlinkedRelatedField(
        view_name='azure-image-detail',
        lookup_field='uuid',
        queryset=models.Image.objects.all(),
    )

    location = serializers.HyperlinkedRelatedField(
        view_name='azure-location-detail',
        lookup_field='uuid',
        queryset=models.Location.objects.all(),
        write_only=True,
    )

    size = serializers.HyperlinkedRelatedField(
        view_name='azure-size-detail',
        lookup_field='uuid',
        queryset=models.Size.objects.all(),
    )

    ssh_public_key = serializers.HyperlinkedRelatedField(
        view_name='sshpublickey-detail',
        lookup_field='uuid',
        queryset=SshPublicKey.objects.all(),
        required=False,
        allow_null=True,
        write_only=True,
        source='ssh_key'
    )

    public_ip = serializers.HyperlinkedRelatedField(
        view_name='azure-public-ip-detail',
        lookup_field='uuid',
        queryset=models.PublicIP.objects.all(),
        required=False,
        allow_null=True,
        write_only=True,
    )

    resource_group = serializers.HyperlinkedRelatedField(
        view_name='azure-resource-group-detail',
        lookup_field='uuid',
        read_only=True,
    )

    class Meta(structure_serializers.VirtualMachineSerializer.Meta):
        model = models.VirtualMachine
        view_name = 'azure-virtualmachine-detail'
        fields = structure_serializers.VirtualMachineSerializer.Meta.fields + (
            'image', 'size', 'user_data', 'runtime_state', 'start_time',
            'cores', 'ram', 'disk', 'image_name', 'location',
            'resource_group', 'public_ip',
        )
        protected_fields = structure_serializers.VirtualMachineSerializer.Meta.protected_fields + (
            'image', 'size', 'user_data',
        )
        read_only_fields = structure_serializers.VirtualMachineSerializer.Meta.read_only_fields + (
            'runtime_state', 'start_time', 'cores', 'ram', 'disk', 'image_name',
        )

    @transaction.atomic
    def create(self, validated_data):
        vm_name = validated_data['name']
        spl = validated_data['service_project_link']
        location = validated_data.pop('location')
        public_ip = validated_data.pop('public_ip', None)

        resource_group_name = 'group{}'.format(vm_name)
        storage_account_name = 'storage{}'.format(hash_string(vm_name.lower(), 14))
        network_name = 'net{}'.format(vm_name)
        subnet_name = 'subnet{}'.format(vm_name)
        nic_name = 'nic{}'.format(vm_name)
        config_name = 'ipconf{}'.format(vm_name)

        resource_group = models.ResourceGroup.objects.create(
            service_project_link=spl,
            name=resource_group_name,
            location=location,
        )

        models.StorageAccount.objects.create(
            service_project_link=spl,
            name=storage_account_name,
            resource_group=resource_group,
        )

        network = models.Network.objects.create(
            service_project_link=spl,
            resource_group=resource_group,
            name=network_name,
            cidr='10.0.0.0/16',
        )

        subnet = models.SubNet.objects.create(
            service_project_link=spl,
            resource_group=resource_group,
            name=subnet_name,
            cidr='10.0.0.0/24',
            network=network,
        )

        nic = models.NetworkInterface.objects.create(
            service_project_link=spl,
            resource_group=resource_group,
            name=nic_name,
            subnet=subnet,
            config_name=config_name,
            public_ip=public_ip,
        )

        validated_data['network_interface'] = nic
        validated_data['resource_group'] = resource_group
        validated_data['username'] = generate_username()
        validated_data['password'] = generate_password()

        return super(VirtualMachineSerializer, self).create(validated_data)


class PublicIPSerializer(structure_serializers.BaseResourceSerializer):
    service = serializers.HyperlinkedRelatedField(
        source='service_project_link.service',
        view_name='azure-detail',
        lookup_field='uuid',
        queryset=models.AzureService.objects.all(),
    )

    service_project_link = serializers.HyperlinkedRelatedField(
        view_name='azure-spl-detail',
        queryset=models.AzureServiceProjectLink.objects.all(),
    )

    location = serializers.HyperlinkedRelatedField(
        view_name='azure-location-detail',
        lookup_field='uuid',
        queryset=models.Location.objects.all(),
    )

    resource_group = serializers.HyperlinkedRelatedField(
        view_name='azure-resource-group-detail',
        lookup_field='uuid',
        queryset=models.ResourceGroup.objects.all(),
    )

    class Meta(object):
        model = models.PublicIP
        view_name = 'azure-public-ip-detail'
        fields = structure_serializers.BaseResourceSerializer.Meta.fields + (
            'location', 'resource_group',
        )
        extra_kwargs = {
            'url': {'lookup_field': 'uuid'},
        }
