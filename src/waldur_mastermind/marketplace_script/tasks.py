import base64
import json
import logging
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.utils import timezone

from waldur_core.core.utils import get_fake_context, get_system_robot
from waldur_core.structure import models as structure_models
from waldur_mastermind.marketplace import models
from waldur_mastermind.marketplace import serializers as marketplace_serializer
from waldur_mastermind.marketplace_script import PLUGIN_NAME, serializers, utils
from waldur_mastermind.marketplace_script import models as marketplace_script_models

logger = logging.getLogger(__name__)


@shared_task(name="waldur_marketplace_script.pull_resources")
def pull_resources():
    for resource in models.Resource.objects.filter(
        offering__type=PLUGIN_NAME,
        offering__secret_options__has_key="pull",
        state__in=[models.Resource.States.OK, models.Resource.States.ERRED],
    ):
        pull_resource.delay(resource.id)


@shared_task
def pull_resource(resource_id):
    resource = models.Resource.objects.get(id=resource_id)

    # We use secret_options the same like in ContainerExecutorMixin.send_request
    options = resource.offering.secret_options
    if "pull" not in options:
        logger.debug("Missing pull script, skipping")
        return
    serializer = serializers.ResourceSerializer(instance=resource)
    environment = {
        key.upper(): json.dumps(value) if isinstance(value, dict | list) else str(value)
        for key, value in dict(serializer.data).items()
    }
    for opt in options.get("environ", []):
        if isinstance(opt, dict):
            environment.update({opt["name"]: opt["value"]})

    language = options["language"]
    image = settings.WALDUR_MARKETPLACE_SCRIPT["DOCKER_IMAGES"].get(language)["image"]
    command = settings.WALDUR_MARKETPLACE_SCRIPT["DOCKER_IMAGES"].get(language)[
        "command"
    ]

    try:
        output = utils.execute_script(
            image=image, command=command, src=options["pull"], environment=environment
        )
        if output:
            last_line = output.splitlines()[-1]
            decoded_metadata = base64.b64decode(last_line)
            updated_values = json.loads(decoded_metadata)
            context = get_fake_context(user=get_system_robot())
            if "usages" in updated_values.keys():
                new_usages = updated_values["usages"]
                rpp = models.ResourcePlanPeriod.objects.get(
                    resource=resource, plan=resource.plan
                ).uuid
                usage_serializer = (
                    marketplace_serializer.ComponentUsageCreateSerializer(
                        data={"usages": new_usages, "plan_period": rpp}, context=context
                    )
                )
                if usage_serializer.is_valid():
                    usage_serializer.save()
                else:
                    logger.error(
                        f"Validation failed when processing reported usage for {resource},"
                        f" usage values {new_usages}, validation errors: {usage_serializer.errors}"
                    )
            if "report" in updated_values.keys():
                new_report = updated_values["report"]
                report_serializer = marketplace_serializer.ResourceReportSerializer(
                    data={"report": new_report}, context=context
                )
                if report_serializer.is_valid():
                    resource.report = report_serializer.validated_data["report"]
                    resource.save(update_fields=["report"])
                else:
                    logger.error(
                        f"Validation failed when processing report for {resource},"
                        f"{new_report}, validation errors: {report_serializer.errors}"
                    )
    except Exception as e:
        resource.set_state_erred()
        if e:
            resource.error_message = str(e).splitlines()[0]
            resource.error_traceback = str(e)
    else:
        if resource.state != models.Resource.States.OK:
            resource.set_state_ok()
            resource.error_message = ""
            resource.error_traceback = ""
    finally:
        resource.save()


@shared_task
def dry_run_executor(dry_run_id):
    dry_run = marketplace_script_models.DryRun.objects.get(id=dry_run_id)
    dry_run.set_state_executing()
    dry_run.save()
    order = dry_run.order
    executor = utils.ContainerExecutorMixin()
    executor.order = order
    executor.hook_type = dry_run.order_type
    dry_run.output = executor.send_request(dry_run.order.created_by, dry_run=True)
    dry_run.save()
    structure_models.Project.objects.filter(id=dry_run.order.project.id).delete()


@shared_task(name="waldur_marketplace_script.remove_old_dry_runs")
def remove_old_dry_runs():
    marketplace_script_models.DryRun.objects.filter(
        state=marketplace_script_models.DryRun.States.DONE,
        created__lt=timezone.now() - timezone.timedelta(days=1),
    ).delete()


@shared_task(
    name="waldur_mastermind.marketplace_script.mark_terminating_resources_as_erred_after_timeout"
)
def mark_terminating_resources_as_erred_after_timeout():
    now = timezone.now()
    two_hours_ago = now - timedelta(hours=2)
    stale_orders = models.Order.objects.filter(
        offering__type=PLUGIN_NAME,
        state=models.Order.States.EXECUTING,
        modified__lt=two_hours_ago,
    )

    for order in stale_orders:
        order.cancel()
        order.save()
        resource = order.resource
        resource.set_state_erred()
        resource.save(update_fields=["state"])


@shared_task
def resource_options_have_been_changed(resource_id, options_old):
    resource = models.Resource.objects.get(id=resource_id)

    options = resource.offering.secret_options
    if "resource_options_handler" not in options:
        logger.debug("Missing resource options handler script, skipping")
        return
    serializer = serializers.ResourceSerializer(instance=resource)
    environment = {
        key.upper(): json.dumps(value) if isinstance(value, dict | list) else str(value)
        for key, value in dict(serializer.data).items()
    }
    for opt in options.get("environ", []):
        if isinstance(opt, dict):
            environment.update({opt["name"]: opt["value"]})
    environment["RESOURCE_OPTIONS_OLD"] = options_old
    environment["RESOURCE_OPTIONS"] = resource.options

    language = options["language"]
    image = settings.WALDUR_MARKETPLACE_SCRIPT["DOCKER_IMAGES"].get(language)["image"]
    command = settings.WALDUR_MARKETPLACE_SCRIPT["DOCKER_IMAGES"].get(language)[
        "command"
    ]

    try:
        utils.execute_script(
            image=image,
            command=command,
            src=options["resource_options_handler"],
            environment=environment,
        )
    except Exception as e:
        resource.set_state_erred()
        if e:
            resource.error_message = str(e).splitlines()[0]
            resource.error_traceback = str(e)
    else:
        if resource.state != models.Resource.States.OK:
            resource.set_state_ok()
            resource.error_message = ""
            resource.error_traceback = ""
    finally:
        resource.save()
