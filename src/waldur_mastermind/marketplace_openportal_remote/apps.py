from django.apps import AppConfig
from django.conf import settings as django_settings
from django.db.models import signals


class MarketplaceOpenPortalRemoteConfig(AppConfig):
    name = "waldur_mastermind.marketplace_openportal_remote"
    verbose_name = "Marketplace OpenPortal Remote"
    service_name = "OpenPortal Remote"

    def ready(self):
        from waldur_core.permissions import signals as permission_signals
        from waldur_mastermind.marketplace import handlers as marketplace_handlers
        from waldur_mastermind.marketplace import models as marketplace_models
        from waldur_mastermind.marketplace.plugins import Component, manager
        from waldur_mastermind.marketplace_openportal_remote import (
            PLUGIN_NAME,
            handlers,
            processor,
        )
        from waldur_mastermind.marketplace_openportal_remote import (
            registrators as openportal_remote_registrators,
        )
        from waldur_openportal.apps import OpenPortalConfig
        from waldur_openportal import models as openportal_models
        from waldur_openportal import signals as openportal_signals

        openportal_remote_registrators.OpenPortalRemoteRegistrator.connect()

        signals.post_save.connect(
            handlers.update_component_quota,
            sender=openportal_models.Allocation,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.update_component_quota",
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
            can_update_limits=True,
            components=(
                Component(
                    type="node",
                    name="NODE",
                    measured_unit="hours",
                    billing_type=USAGE,
                    limit_period=TOTAL,
                    limit_amount=openportal_remote_registrators.OpenPortalRemoteRegistrator.convert_quantity(
                        default_limits["NODE"], "node"
                    ),
                ),
            ),
            service_type=OpenPortalConfig.service_name,
        )

        openportal_signals.openportal_association_created.connect(
            handlers.create_offering_user_for_openportal_remote_user,
            sender=openportal_models.Allocation,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.create_offering_user_for_openportal_remote_user",
        )

        openportal_signals.openportal_association_deleted.connect(
            handlers.drop_offering_user_for_openportal_remote_user,
            sender=openportal_models.Allocation,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.drop_offering_user_for_openportal_remote_user",
        )

        signals.post_save.connect(
            handlers.sync_component_user_usage_when_allocation_user_usage_is_submitted,
            sender=openportal_models.AllocationUserUsage,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.sync_component_user_usage_when_allocation_user_usage_is_submitted",
        )

        signals.post_save.connect(
            handlers.send_done_order_to_message_queue,
            sender=marketplace_models.Order,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.send_done_order_to_message_queue",
        )

        signals.post_save.connect(
            handlers.send_pending_order_to_message_queue,
            sender=marketplace_models.Order,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.send_pending_order_to_message_queue",
        )

        signals.post_save.connect(
            handlers.send_offering_user_username_message,
            sender=marketplace_models.OfferingUser,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.send_offering_user_username_message",
        )

        signals.post_save.connect(
            handlers.send_resource_update_message_to_mqtt,
            sender=marketplace_models.Resource,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.send_resource_status_changed_message_to_mqtt",
        )

        permission_signals.role_granted.connect(
            handlers.send_role_granted_message_to_mqtt,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.send_role_granted_message_to_mqtt",
        )

        permission_signals.role_revoked.connect(
            handlers.send_role_revoked_message_to_mqtt,
            dispatch_uid="waldur_mastermind.marketplace_openportal_remote.send_role_revoked_message_to_mqtt",
        )
