from waldur_mastermind.marketplace import processors
from waldur_openportal import views as openportal_views


class CreateAllocationProcessor(processors.BaseCreateResourceProcessor):
    viewset = openportal_views.AllocationViewSet

    fields = (
        "name",
        "description",
    )


class DeleteAllocationProcessor(processors.DeleteScopedResourceProcessor):
    viewset = openportal_views.AllocationViewSet
