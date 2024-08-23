from django.utils.functional import cached_property

from waldur_core.structure.tests.fixtures import ProjectFixture

from . import factories


class OpenPortalFixture(ProjectFixture):
    @cached_property
    def settings(self):
        return factories.OpenPortalServiceSettingsFactory(customer=self.customer)

    @cached_property
    def allocation(self):
        return factories.AllocationFactory(
            service_settings=self.settings,
            project=self.project,
        )

    @cached_property
    def association(self):
        return factories.AssociationFactory(allocation=self.allocation)
