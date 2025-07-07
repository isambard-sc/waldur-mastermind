import logging

from django.core import exceptions as django_exceptions
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.utils import timezone

from waldur_core.core.utils import month_start
from waldur_core.logging import tasks as logging_tasks
from waldur_core.logging import utils as logging_utils
from waldur_core.permissions import models as permission_models
from waldur_core.structure import models as structure_models
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace import utils as marketplace_utils
from waldur_mastermind.marketplace.enums import OrderStates, ResourceStates
from waldur_mastermind.marketplace.plugins import manager
from waldur_mastermind.marketplace_openportal_remote import PLUGIN_NAME, utils

logger = logging.getLogger(__name__)

COMPONENT_FIELDS = {
    "node_usage",
    "node_limit",
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

    new_limits = {}
    new_usages = {}
    for component in manager.get_components(PLUGIN_NAME):
        usage = float(getattr(allocation, component.type + "_usage"))
        limit = float(getattr(allocation, component.type + "_limit"))

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
            new_limits[component.type] = limit
            new_usages[component.type] = usage
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

    logger.info(f"Old limits: {resource.limits}, new limits: {new_limits}")

    if resource.limits != new_limits:
        logger.debug(
            "Syncing limits for OpenPortal Remote. Allocation ID: %s. Old limits: %s. New limits: %s",
            allocation.id,
            resource.limits,
            new_limits,
        )
        resource.limits = new_limits
        resource.save(update_fields=["limits"])

    if resource.current_usages != new_usages:
        logger.debug(
            "Syncing usages for OpenPortal Remote. Allocation ID: %s. Old usages: %s. New usages: %s",
            allocation.id,
            resource.current_usages,
            new_usages,
        )
        resource.current_usages = new_usages
        resource.save(update_fields=["current_usages"])


def create_offering_user_for_openportal_remote_user(sender, allocation, user, **kwargs):
    logger.info(
        f"OpenPortal Remote - creating offering user for user {user} in {allocation}"
    )
    try:
        offering = marketplace_models.Offering.objects.get(
            scope=allocation.service_settings
        )
    except marketplace_models.Offering.DoesNotExist:
        logger.warning(
            "Skipping OpenPortal Remote user synchronization because offering is not found. "
            "OpenPortal settings ID: %s",
            allocation.service_settings_id,
        )
        return

    marketplace_models.OfferingUser.objects.update_or_create(
        offering=offering,
        user=user,
    )


def drop_offering_user_for_openportal_remote_user(sender, allocation, user, **kwargs):
    logger.info(
        f"OpenPortal Remote - dropping offering user for user {user} in {allocation}"
    )
    try:
        offering = marketplace_models.Offering.objects.get(
            scope=allocation.service_settings
        )
    except marketplace_models.Offering.DoesNotExist:
        logger.warning(
            "Skipping OpenPortal Remote user synchronization because offering is not found. "
            "OpenPortal settings ID: %s",
            allocation.service_settings_id,
        )
        return

    marketplace_models.OfferingUser.objects.filter(
        offering=offering, user=user
    ).delete()


def sync_component_user_usage_when_allocation_user_usage_is_submitted(
    sender, instance, **kwargs
):
    marketplace_utils.sync_component_user_usage(instance, PLUGIN_NAME)


def send_done_order_to_message_queue(sender, instance, created=False, **kwargs):
    order: marketplace_models.Order = instance
    if created:
        return
    offering = order.offering
    if offering.type != PLUGIN_NAME:
        return

    if not order.tracker.has_changed("state") or order.state != OrderStates.DONE:
        return

    payload = {"order_uuid": order.uuid.hex}
    messages = utils.prepare_messages(
        offering, payload, logging_utils.ObservableObjectType.ORDER
    )
    if messages:
        logging_tasks.publish_messages.delay(messages)


def send_pending_order_to_message_queue(sender, instance, created=False, **kwargs):
    order: marketplace_models.Order = instance
    if created:
        return

    offering = order.offering
    if offering.type != PLUGIN_NAME:
        return

    if (
        not order.tracker.has_changed("state")
        or order.state != OrderStates.PENDING_PROVIDER
    ):
        return

    payload = {"order_uuid": order.uuid.hex}
    messages = utils.prepare_messages(
        offering, payload, logging_utils.ObservableObjectType.ORDER
    )
    if messages:
        logging_tasks.publish_messages.delay(messages)


def send_offering_user_username_message(sender, instance, created=False, **kwargs):
    if not created:
        return
    offering_user: marketplace_models.OfferingUser = instance
    offering = offering_user.offering
    if offering.type != PLUGIN_NAME:
        return

    if not offering_user.tracker.has_changed("username"):
        return

    if not offering_user.username:
        return

    payload = {
        "username": offering_user.username,
        "offering_user_uuid": offering_user.uuid.hex,
        "user_uuid": offering_user.user.uuid.hex,
    }
    messages = utils.prepare_messages(
        offering_user.offering,
        payload,
        logging_utils.ObservableObjectType.OFFERING_USER,
    )
    if messages:
        logging_tasks.publish_messages.delay(messages)


def process_role_changed(permission: permission_models.UserRole, granted: bool):
    if not isinstance(permission.scope, structure_models.Project):
        return

    project = permission.scope
    offering_ids = set(
        project.resource_set.filter(
            state=ResourceStates.OK,
            offering__type=PLUGIN_NAME,
        ).values_list("offering", flat=True)
    )

    if not offering_ids:
        return

    user = permission.user
    offerings = marketplace_models.Offering.objects.filter(id__in=offering_ids)

    all_messages = []
    for offering in offerings:
        logger.debug(
            "Processing user role changed event for project %s, offering %s, user %s, granted: %s",
            project,
            offering,
            user,
            granted,
        )
        payload = {
            "user_uuid": user.uuid.hex,
            "user_username": user.username,
            "project_uuid": project.uuid.hex,
            "project_name": project.name,
            "role_name": permission.role.name,
            "granted": granted,
        }
        messages = utils.prepare_messages(
            offering, payload, logging_utils.ObservableObjectType.USER_ROLE
        )
        all_messages.extend(messages)

    if all_messages:
        logging_tasks.publish_messages.delay(all_messages)


def send_role_revoked_message_to_mqtt(
    sender, instance: permission_models.UserRole, **kwargs
):
    process_role_changed(instance, False)


def send_role_granted_message_to_mqtt(
    sender, instance: permission_models.UserRole, **kwargs
):
    process_role_changed(instance, True)


def send_resource_update_message_to_mqtt(
    sender, instance: marketplace_models.Resource, created=False, **kwargs
):
    if created:
        return

    offering = instance.offering
    if offering.type != PLUGIN_NAME:
        return

    if not any(
        instance.tracker.has_changed(field_name)
        for field_name in ["downscaled", "restrict_member_access", "paused", "limits"]
    ):
        return

    utils.push_resource_update_message(instance)
