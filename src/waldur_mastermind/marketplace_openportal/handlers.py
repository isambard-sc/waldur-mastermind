import logging

from django.core import exceptions as django_exceptions
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.utils import timezone

from waldur_core.core.utils import month_start
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace.plugins import manager
from waldur_mastermind.marketplace_openportal import PLUGIN_NAME
from waldur_openportal import models as openportal_models

logger = logging.getLogger(__name__)

COMPONENT_FIELDS = {
    "cpu_usage",
    "gpu_usage",
    "ram_usage",
    "cpu_limit",
    "gpu_limit",
    "ram_limit",
}


def update_component_quota(sender, instance, created=False, **kwargs):
    if created:
        return

    if not set(instance.tracker.changed()) & COMPONENT_FIELDS:
        return

    allocation = instance

    try:
        resource = marketplace_models.Resource.objects.get(scope=allocation)
    except django_exceptions.ObjectDoesNotExist:
        return

    for component in manager.get_components(PLUGIN_NAME):
        usage = getattr(allocation, component.type + "_usage")
        limit = getattr(allocation, component.type + "_limit")

        try:
            offering_component = marketplace_models.OfferingComponent.objects.get(
                offering=resource.offering, type=component.type
            )
        except marketplace_models.OfferingComponent.DoesNotExist:
            logger.warning(
                "Skipping Allocation synchronization because this "
                "marketplace.OfferingComponent does not exist."
                "Allocation ID: %s",
                allocation.id,
            )
        else:
            marketplace_models.ComponentQuota.objects.update_or_create(
                resource=resource,
                component=offering_component,
                defaults={"limit": limit, "usage": usage},
            )
            try:
                plan_period = marketplace_models.ResourcePlanPeriod.objects.get(
                    resource=resource, end=None
                )
            except (ObjectDoesNotExist, MultipleObjectsReturned):
                logger.warning(
                    "Skipping component usage synchronization because valid"
                    "ResourcePlanPeriod is not found."
                    "Allocation ID: %s",
                    allocation.id,
                )
            else:
                date = timezone.now()
                marketplace_models.ComponentUsage.objects.update_or_create(
                    resource=resource,
                    component=offering_component,
                    billing_period=month_start(date),
                    plan_period=plan_period,
                    defaults={"usage": usage, "date": date},
                )


def terminate_allocation_when_resource_is_terminated(sender, instance, **kwargs):
    resource: marketplace_models.Resource = instance
    if resource.offering.type != PLUGIN_NAME:
        return

    allocation: openportal_models.Allocation = resource.scope
    allocation.begin_deleting()
    allocation.save(update_fields=["state"])
