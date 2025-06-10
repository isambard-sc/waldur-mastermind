from django.apps import AppConfig
from django.db.models import signals


class OpenPortalConfig(AppConfig):
    name = "waldur_openportal"
    verbose_name = "OpenPortal"
    service_name = "OpenPortal"

    def ready(self):
        from waldur_core.core import models as core_models
        from waldur_core.permissions import signals as permission_signals
        from waldur_core.quotas import models as quota_models
        from waldur_core.quotas.fields import CounterQuotaField, QuotaField
        from waldur_core.structure import models as structure_models
        from waldur_core.structure.registry import SupportedServices

        from . import handlers, models, utils
        from .backend import OpenPortalBackend

        SupportedServices.register_backend(OpenPortalBackend)

        for model in (structure_models.Customer, structure_models.Project):
            signals.post_save.connect(
                handlers.schedule_creation_sync,
                sender=model,
                dispatch_uid="waldur_openportal.handlers.schedule_sync_on_%s_creation"
                % model.__class__,
            )

            signals.pre_delete.connect(
                handlers.schedule_deletion_sync,
                sender=model,
                dispatch_uid="waldur_openportal.handlers.schedule_sync_on_%s_deletion"
                % model.__class__,
            )

        signals.post_save.connect(
            handlers.update_user,
            sender=core_models.User,
            dispatch_uid="waldur_openportal.handlers.update_user",
        )

        signals.pre_delete.connect(
            handlers.delete_user,
            sender=core_models.User,
            dispatch_uid="waldur_openportal.handlers.delete_user",
        )

        signals.post_save.connect(
            handlers.schedule_sync_on_quota_change,
            sender=quota_models.QuotaLimit,
            dispatch_uid="waldur_openportal.handlers.schedule_sync_on_quota_save",
        )

        permission_signals.role_granted.connect(
            handlers.role_granted,
            dispatch_uid="waldur_openportal.handlers.role_granted",
        )

        permission_signals.role_revoked.connect(
            handlers.role_revoked,
            dispatch_uid="waldur_openportal.handlers.role_revoked",
        )

        for quota in utils.QUOTA_NAMES:
            structure_models.Customer.add_quota_field(
                name=quota, quota_field=QuotaField(is_backend=True)
            )

            structure_models.Project.add_quota_field(
                name=quota, quota_field=QuotaField(is_backend=True)
            )

        structure_models.Project.add_quota_field(
            name="op_allocation_count",
            quota_field=CounterQuotaField(
                target_models=lambda: [models.Allocation],
                path_to_scope="project",
            ),
        )

        structure_models.Customer.add_quota_field(
            name="op_allocation_count",
            quota_field=CounterQuotaField(
                target_models=lambda: [models.Allocation],
                path_to_scope="project.customer",
            ),
        )

        signals.post_save.connect(
            handlers.update_quotas_on_allocation_usage_update,
            sender=models.Allocation,
            dispatch_uid="waldur_openportal.handlers.update_quotas_on_allocation_usage_update",
        )
