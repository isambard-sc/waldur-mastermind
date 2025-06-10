from waldur_mastermind.marketplace import processors
from waldur_openportal import models as openportal_models
from waldur_openportal import views as openportal_views


class CreateRemoteAllocationProcessor(processors.BaseCreateResourceProcessor):
    viewset = openportal_views.RemoteAllocationViewSet

    fields = (
        "name",
        "description",
    )


class DeleteRemoteAllocationProcessor(processors.DeleteScopedResourceProcessor):
    viewset = openportal_views.RemoteAllocationViewSet


class UpdateRemoteAllocationLimitsProcessor(processors.BasicUpdateResourceProcessor):
    def update_limits_process(self, user):
        allocation: openportal_models.RemoteAllocation = self.order.resource.scope
        allocation.schedule_updating()
        allocation.save(update_fields=["state"])

        return False
