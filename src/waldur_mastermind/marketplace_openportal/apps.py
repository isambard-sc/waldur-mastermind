from django.apps import AppConfig
from django.conf import settings as django_settings
from django.db.models import signals


class MarketplaceOpenPortalConfig(AppConfig):
    name = "waldur_mastermind.marketplace_openportal"
    verbose_name = "Marketplace OPENPORTAL"

    def ready(self):
        from waldur_mastermind.marketplace import handlers as marketplace_handlers
        from waldur_mastermind.marketplace import models as marketplace_models
        from waldur_mastermind.marketplace.plugins import Component, manager
        from waldur_mastermind.marketplace_openportal import PLUGIN_NAME
        from waldur_openportal import models as openportal_models
        from waldur_openportal import signals as openportal_signals
        from waldur_openportal.apps import OpenPortalConfig

        from . import handlers, processor
        from . import registrators as openportal_registrators

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

        USAGE = marketplace_models.OfferingComponent.BillingTypes.USAGE
        TOTAL = marketplace_models.OfferingComponent.LimitPeriods.TOTAL
        default_limits = django_settings.WALDUR_OPENPORTAL["DEFAULT_LIMITS"]
        manager.register(
            PLUGIN_NAME,
            create_resource_processor=processor.CreateAllocationProcessor,
            delete_resource_processor=processor.DeleteAllocationProcessor,
            components=(
                Component(
                    type="cpu",
                    name="CPU",
                    measured_unit="hours",
                    billing_type=USAGE,
                    limit_period=TOTAL,
                    limit_amount=openportal_registrators.OpenPortalRegistrator.convert_quantity(
                        default_limits["CPU"], "cpu"
                    ),
                ),
                Component(
                    type="gpu",
                    name="GPU",
                    measured_unit="hours",
                    billing_type=USAGE,
                    limit_period=TOTAL,
                    limit_amount=openportal_registrators.OpenPortalRegistrator.convert_quantity(
                        default_limits["GPU"], "gpu"
                    ),
                ),
                Component(
                    type="ram",
                    name="RAM",
                    measured_unit="GB-hours",
                    billing_type=USAGE,
                    limit_period=TOTAL,
                    limit_amount=openportal_registrators.OpenPortalRegistrator.convert_quantity(
                        default_limits["RAM"], "ram"
                    ),
                ),
            ),
            service_type=OpenPortalConfig.service_name,
        )

        openportal_signals.openportal_association_created.connect(
            handlers.create_offering_user_for_openportal_user,
            sender=openportal_models.Allocation,
            dispatch_uid="waldur_mastermind.marketplace_openportal.create_offering_user_for_openportal_user",
        )

        openportal_signals.openportal_association_deleted.connect(
            handlers.drop_offering_user_for_openportal_user,
            sender=openportal_models.Allocation,
            dispatch_uid="waldur_mastermind.marketplace_openportal.drop_offering_user_for_openportal_user",
        )
