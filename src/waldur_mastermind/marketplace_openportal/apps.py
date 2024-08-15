from django.apps import AppConfig
from django.db.models import signals


class MarketplaceOpenPortalConfig(AppConfig):
    name = "waldur_mastermind.marketplace_openportal"
    verbose_name = "Marketplace OpenPortal"
    service_name = "OpenPortal"

    def ready(self):
        from waldur_mastermind.marketplace import handlers as marketplace_handlers
        from waldur_mastermind.marketplace import models as marketplace_models
        from waldur_mastermind.marketplace import signals as marketplace_signals
        from waldur_mastermind.marketplace.plugins import manager
        from waldur_mastermind.marketplace_openportal import (
            PLUGIN_NAME,
            handlers,
            processor,
        )
        from waldur_mastermind.marketplace_openportal import (
            registrators as openportal_registrators,
        )
        from waldur_openportal import models as openportal_models

        openportal_registrators.OpenPortalRegistrator.connect()

        signals.post_save.connect(
            handlers.update_component_quota,
            sender=openportal_models.Allocation,
            dispatch_uid="waldur_mastermind.marketplace_openportal.update_component_quota",
        )

        marketplace_handlers.connect_resource_handlers(openportal_models.Allocation)
        marketplace_handlers.connect_resource_metadata_handlers(
            openportal_models.Allocation
        )

        manager.register(
            PLUGIN_NAME,
            create_resource_processor=processor.CreateAllocationProcessor,
            update_resource_processor=processor.UpdateAllocationLimitsProcessor,
            delete_resource_processor=processor.DeleteAllocationProcessor,
            can_update_limits=True,
        )

        marketplace_signals.resource_deletion_succeeded.connect(
            handlers.terminate_allocation_when_resource_is_terminated,
            sender=marketplace_models.Resource,
            dispatch_uid="waldur_mastermind.marketplace_openportal.terminate_allocation_when_resource_is_terminated",
        )
