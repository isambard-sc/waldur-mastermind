from django.apps import AppConfig
from django.conf import settings as django_settings
from django.db.models import signals


class MarketplaceOpenPortalConfig(AppConfig):
    name = "waldur_mastermind.marketplace_openportal"
    verbose_name = "Marketplace OpenPortal"
    service_name = "OpenPortal"

    def ready(self):
        from waldur_core.permissions import signals as permission_signals
        from waldur_mastermind.marketplace import handlers as marketplace_handlers
        from waldur_mastermind.marketplace import models as marketplace_models
        from waldur_mastermind.marketplace.plugins import Component, manager
        from waldur_mastermind.marketplace_openportal import (
            PLUGIN_NAME,
            handlers,
            processor,
        )
        from waldur_mastermind.marketplace_openportal import (
            registrators as openportal_registrators,
        )
        from waldur_openportal.apps import OpenPortalConfig
        from waldur_openportal import models as openportal_models
        from waldur_openportal import signals as openportal_signals

        openportal_registrators.OpenPortalRegistrator.connect()

        signals.post_save.connect(
            handlers.update_component_quota,
            sender=openportal_models.Allocation,
            dispatch_uid="waldur_mastermind.marketplace_openportal.update_component_quota",
        )

        marketplace_handlers.connect_resource_handlers(openportal_models.Allocation)
        marketplace_handlers.connect_resource_metadata_handlers(openportal_models.Allocation)

        USAGE = marketplace_models.OfferingComponent.BillingTypes.USAGE
        TOTAL = marketplace_models.OfferingComponent.LimitPeriods.TOTAL
        default_limits = django_settings.WALDUR_OPENPORTAL["DEFAULT_LIMITS"]

        manager.register(
            PLUGIN_NAME,
            create_resource_processor=processor.CreateAllocationProcessor,
            update_resource_processor=processor.UpdateAllocationLimitsProcessor,
            delete_resource_processor=processor.DeleteAllocationProcessor,
            can_update_limits=True,
            components=(
                Component(
                    type="node",
                    name="NODE",
                    measured_unit="hours",
                    billing_type=USAGE,
                    limit_period=TOTAL,
                    limit_amount=openportal_registrators.OpenPortalRegistrator.convert_quantity(
                        default_limits["NODE"], "node"
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

        signals.post_save.connect(
            handlers.sync_component_user_usage_when_allocation_user_usage_is_submitted,
            sender=openportal_models.AllocationUserUsage,
            dispatch_uid="waldur_mastermind.marketplace_openportal.sync_component_user_usage_when_allocation_user_usage_is_submitted",
        )

        signals.post_save.connect(
            handlers.send_order_created_to_mqtt,
            sender=marketplace_models.Order,
            dispatch_uid="waldur_mastermind.marketplace_openportal.send_order_created_to_mqtt",
        )

        signals.post_save.connect(
            handlers.send_resource_update_message_to_mqtt,
            sender=marketplace_models.Resource,
            dispatch_uid="waldur_mastermind.marketplace_openportal.send_resource_status_changed_message_to_mqtt",
        )

        permission_signals.role_granted.connect(
            handlers.send_role_granted_message_to_mqtt,
            dispatch_uid="waldur_mastermind.marketplace_openportal.send_role_granted_message_to_mqtt",
        )

        permission_signals.role_revoked.connect(
            handlers.send_role_revoked_message_to_mqtt,
            dispatch_uid="waldur_mastermind.marketplace_openportal.send_role_revoked_message_to_mqtt",
        )
