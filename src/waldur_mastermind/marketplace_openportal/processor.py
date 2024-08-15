from django.db import transaction

from waldur_core.structure.models import ServiceSettings
from waldur_mastermind.marketplace import processors
from waldur_openportal import models as openportal_models

from .apps import MarketplaceOpenPortalConfig


class CreateAllocationProcessor(processors.BasicCreateResourceProcessor):
    def process_order(self, user):
        with transaction.atomic():
            service_settings, _ = ServiceSettings.objects.update_or_create(
                type=MarketplaceOpenPortalConfig.service_name,
                state=ServiceSettings.States.OK,
                shared=True,
                defaults={
                    "name": "OpenPortal service settings",
                    "is_active": False,
                },
            )

            allocation = openportal_models.Allocation.objects.create(
                name=self.order.attributes["name"],
                service_settings=service_settings,
                project=self.order.project,
            )
            self.order.resource.scope = allocation
            self.order.resource.save()


class DeleteAllocationProcessor(processors.BasicDeleteResourceProcessor):
    def process_order(self, user):
        with transaction.atomic():
            marketplace_resource = self.order.resource
            marketplace_resource.set_state_terminating()
            marketplace_resource.save(update_fields=["state"])

            allocation: openportal_models.Allocation = marketplace_resource.scope
            allocation.schedule_deleting()
            allocation.save(update_fields=["state"])


class UpdateAllocationLimitsProcessor(processors.BasicUpdateResourceProcessor):
    def update_limits_process(self, user):
        allocation: openportal_models.Allocation = self.order.resource.scope
        allocation.schedule_updating()
        allocation.save(update_fields=["state"])

        return False
