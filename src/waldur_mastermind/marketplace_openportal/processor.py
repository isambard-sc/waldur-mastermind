from waldur_mastermind.marketplace import processors
from waldur_openportal import models as openportal_models
from waldur_openportal import views as openportal_views

from .apps import MarketplaceOpenPortalConfig


class CreateAllocationProcessor(processors.BaseCreateResourceProcessor):
    viewset = openportal_views.AllocationViewSet

    fields = (
        "name",
        "description",
    )


class DeleteAllocationProcessor(processors.DeleteScopedResourceProcessor):
    viewset = openportal_views.AllocationViewSet


class UpdateAllocationLimitsProcessor(processors.BasicUpdateResourceProcessor):
    def update_limits_process(self, user):
        allocation: openportal_models.Allocation = self.order.resource.scope
        allocation.schedule_updating()
        allocation.save(update_fields=["state"])

        return False
