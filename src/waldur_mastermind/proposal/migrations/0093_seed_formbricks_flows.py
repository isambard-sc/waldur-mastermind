"""Move Formbricks flows from code/YAML into the database.

Flows used to live in proposal/formbricks_flows.py (_DEFAULT_FORM_FLOWS) or a
mounted WALDUR_BASE_CONFIG_DIR/formbricks-flows.yaml. This seeds
FormbricksFlow rows from the YAML file when one is mounted, otherwise from a
frozen copy of those defaults, and points each Call at the flow its old
formbricks_flow_key named.
"""

import logging
import os

import yaml
from django.db import migrations

logger = logging.getLogger(__name__)

_PROJECT_DETAILS_STEP = {
    "key": "project_details",
    "survey_id": "cmt4q1c400004qe01zta9vmnm",
    "field_map": {
        "fjxcnvv5q1ny48q2wazmq2eb": "name",
        "drihiecfnvzubpjfjc39ai6p": "project_summary",
    },
    "resource_question_id": "peoi4op1vjaws6c2dvigbahe",
    "resource_label_to_slug": {"Isambard-AI": "isambard-a-1"},
    "resource_options": {
        "isambard-a-1": {
            "attribute_field_map": {"u3bpmiiaumhqqhjk9yrdet6u": "allocation"},
            "default_attributes": {},
        },
    },
    "mapper": "map_project_details",
}
_TEAM_DETAILS_STEP = {"key": "team_details", "survey_id": "cmt4qbc2g0005qe0143hnuqqs"}
_COMPLIANCE_STEP = {"key": "compliance", "survey_id": "cmt4rw5cp0008qe01g0dvhrbb"}

DEFAULT_FORM_FLOWS = {
    "AIRR-GW": [
        _PROJECT_DETAILS_STEP,
        _TEAM_DETAILS_STEP,
        _COMPLIANCE_STEP,
        {"key": "assessment", "survey_id": "cmt4qby6u0006qe01dd81j1ew"},
    ],
    "AIRR-RA": [
        _PROJECT_DETAILS_STEP,
        _TEAM_DETAILS_STEP,
        _COMPLIANCE_STEP,
        {"key": "assessment", "survey_id": "cmt4qc2ey0007qe011sx23uti"},
    ],
}

# Previously hard-coded as formbricks_flows.REVIEWER_VISIBLE_STEPS.
REVIEWER_VISIBLE_STEPS = {"project_details", "assessment"}

FIELD_MAP_VALUE_TYPES = {
    "field_map": "text",
    "integer_field_map": "integer",
    "boolean_field_map": "boolean",
}


def load_form_flows():
    config_dir = os.environ.get("WALDUR_BASE_CONFIG_DIR", "/etc/waldur")
    path = os.path.join(config_dir, "formbricks-flows.yaml")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return DEFAULT_FORM_FLOWS


def seed_flows(apps, schema_editor):
    FormbricksFlow = apps.get_model("proposal", "FormbricksFlow")
    FormbricksFlowStep = apps.get_model("proposal", "FormbricksFlowStep")
    FormbricksFieldMapping = apps.get_model("proposal", "FormbricksFieldMapping")
    FormbricksResourceOption = apps.get_model("proposal", "FormbricksResourceOption")
    Offering = apps.get_model("marketplace", "Offering")
    Call = apps.get_model("proposal", "Call")

    flows_by_key = {}
    for flow_key, steps in load_form_flows().items():
        flow = FormbricksFlow.objects.create(name=flow_key)
        flows_by_key[flow_key] = flow

        for order, step_data in enumerate(steps):
            step = FormbricksFlowStep.objects.create(
                flow=flow,
                order=order,
                key=step_data["key"],
                survey_id=step_data["survey_id"],
                mapper=step_data.get("mapper") or "",
                is_reviewer_visible=step_data["key"] in REVIEWER_VISIBLE_STEPS,
                resource_question_id=step_data.get("resource_question_id") or "",
            )

            for map_key, value_type in FIELD_MAP_VALUE_TYPES.items():
                for question_id, field_name in (step_data.get(map_key) or {}).items():
                    FormbricksFieldMapping.objects.create(
                        step=step,
                        question_id=question_id,
                        proposal_field=field_name,
                        value_type=value_type,
                    )

            resource_options = step_data.get("resource_options") or {}
            seen_offering_ids = set()
            for label, slug in (step_data.get("resource_label_to_slug") or {}).items():
                option = resource_options.get(slug)
                offering = Offering.objects.filter(slug=slug).first()
                if (
                    option is None
                    or offering is None
                    or offering.id in seen_offering_ids
                ):
                    logger.warning(
                        "Formbricks flow %s step %s: skipping resource option "
                        "%r (offering slug %r not found or already mapped).",
                        flow_key,
                        step.key,
                        label,
                        slug,
                    )
                    continue
                seen_offering_ids.add(offering.id)
                FormbricksResourceOption.objects.create(
                    step=step,
                    choice_label=label,
                    offering=offering,
                    attribute_field_map=option.get("attribute_field_map") or {},
                    default_attributes=option.get("default_attributes") or {},
                )

    for call in Call.objects.exclude(formbricks_flow_key__isnull=True).exclude(
        formbricks_flow_key=""
    ):
        flow = flows_by_key.get(call.formbricks_flow_key)
        if flow is None:
            logger.warning(
                "Call %s uses unknown Formbricks flow key %r; leaving it "
                "without a flow.",
                call.uuid,
                call.formbricks_flow_key,
            )
            continue
        call.formbricks_flow = flow
        call.save(update_fields=["formbricks_flow"])


class Migration(migrations.Migration):
    dependencies = [
        ("proposal", "0092_formbricks_flow_models"),
    ]

    operations = [
        migrations.RunPython(seed_flows, migrations.RunPython.noop),
    ]
