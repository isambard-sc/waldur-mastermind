from __future__ import unicode_literals

import django_filters

from waldur_core.core import filters as core_filters
from waldur_core.structure import filters as structure_filters

from . import models


class ServiceProjectLinkFilter(structure_filters.BaseServiceProjectLinkFilter):
    service = core_filters.URLFilter(view_name='vmware-detail', name='service__uuid')

    class Meta(structure_filters.BaseServiceProjectLinkFilter.Meta):
        model = models.VMwareServiceProjectLink


class VirtualMachineFilter(structure_filters.BaseResourceFilter):
    class Meta(structure_filters.BaseResourceFilter.Meta):
        model = models.VirtualMachine
        fields = structure_filters.BaseResourceFilter.Meta.fields + ('runtime_state',)


class DiskFilter(structure_filters.BaseResourceFilter):
    class Meta(structure_filters.BaseResourceFilter.Meta):
        model = models.Disk

    vm = core_filters.URLFilter(view_name='vmware-virtual-machine-detail', name='vm__uuid')
    vm_uuid = django_filters.UUIDFilter(name='vm__uuid')


class TemplateFilter(structure_filters.ServicePropertySettingsFilter):
    class Meta(structure_filters.ServicePropertySettingsFilter.Meta):
        model = models.Template


class ClusterFilter(structure_filters.ServicePropertySettingsFilter):
    customer_uuid = django_filters.UUIDFilter(method='filter_customer', label='Customer uuid')

    def filter_customer(self, queryset, name, value):
        return queryset.filter(customercluster__customer__uuid=value)

    class Meta(structure_filters.ServicePropertySettingsFilter.Meta):
        model = models.Cluster
