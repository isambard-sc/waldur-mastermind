"""Static configuration for Formbricks-driven proposal intake.

Each Call that uses Formbricks (Call.formbricks_flow_key is set) maps to an
entry in FORM_FLOWS: an ordered list of step dicts describing the chain of
Formbricks surveys an applicant fills in, in order.

Step dict shape:
    key:       stable identifier for this step within the flow, e.g.
               "project_details". Used to look up the next step, to decide
               reviewer visibility (see REVIEWER_VISIBLE_STEPS), and stored
               on FormStepResponse.step_key.
    survey_id: the Formbricks survey ID for this step.
    field_map: (optional) {formbricks_question_id: proposal_field_name}.
               Only present on steps whose answers feed directly into
               Proposal fields - currently only "project_details". Steps
               without a field_map (team_details, compliance, assessment)
               are still snapshotted (see models.FormStepResponse) but are
               never turned into structured Waldur data.
    mapper:    (optional) name of a function in formbricks_mapper.py that
               knows how to apply field_map plus any step-specific logic
               (e.g. resource selection) to a Proposal.
    resource_question_id / resource_options: (optional, "project_details"
               only) - see below.
"""

PROJECT_DETAILS_STEP = {
    "key": "project_details",
    "survey_id": "cmt4q1c400004qe01zta9vmnm",
    "field_map": {
        # "What is the title of your project?"
        "cid9d22768jyf65hht3sakqq": "name",
        # "Briefly summarise your project"
        "kfxb1byod4zd0k64o8es2cn9": "project_summary",
        # "How many days of access do you need?"
        "g81oicc5tihv86395lclkfpz": "duration_in_days",
        # "Is this project confidential?"
        "uwuf2cmxqmka9u06g226vhxc": "project_is_confidential",
        # "Does this project have a civilian purpose?"
        "vah5dve0ku0q1acndbctfbmc": "project_has_civilian_purpose",
    },
    # Multi-select: "Which resource types would you like to request?"
    # Options are offering slugs (stable across calls); the mapper resolves
    # each selected slug to *this call's* RequestedOffering row, since the
    # same project_details survey is reused across calls with different
    # RequestedOffering rows for the "same" marketplace offering.
    "resource_question_id": "tf4lhp5vsvc7993sx27q5ugd",
    "resource_options": {
        "isambard-ai": {
            "attribute_field_map": {
                "j4b388ormyl4jiwajx158uel": "num_gpus",
            },
            "default_attributes": {"storage_gb": 100},
        },
        "zenith": {
            "attribute_field_map": {
                "j4b388ormyl4jiwajx158uel": "num_gpus",
            },
            "default_attributes": {"storage_gb": 200},
        },
    },
    "mapper": "map_project_details",
}

TEAM_DETAILS_STEP = {
    "key": "team_details",
    "survey_id": "cmt4qbc2g0005qe0143hnuqqs",
}

COMPLIANCE_STEP = {
    "key": "compliance",
    "survey_id": "cmt4rw5cp0008qe01g0dvhrbb",
}

# No field_map/mapper: assessment answers are read-only reference material
# for the reviewer, who records their own judgement on the Review model
# (summary_score, summary_public_comment, ...) rather than having any
# applicant answer poured into a Proposal field. Still snapshotted (every
# step is - see models.FormStepResponse) and still in
# REVIEWER_VISIBLE_STEPS below.
CALL_GW_ASSESSMENT_STEP = {
    "key": "assessment",
    "survey_id": "cmt4qby6u0006qe01dd81j1ew",
}
CALL_RA_ASSESSMENT_STEP = {
    "key": "assessment",
    "survey_id": "cmt4qc2ey0007qe011sx23uti",
}

# Keys here are arbitrary Waldur-side identifiers - set Call.formbricks_flow_key
# to one of these keys on the real Call rows once they exist.
FORM_FLOWS = {
    "AIRR-GW": [
        PROJECT_DETAILS_STEP,
        TEAM_DETAILS_STEP,
        COMPLIANCE_STEP,
        CALL_GW_ASSESSMENT_STEP,
    ],
    "AIRR-RA": [
        PROJECT_DETAILS_STEP,
        TEAM_DETAILS_STEP,
        COMPLIANCE_STEP,
        CALL_RA_ASSESSMENT_STEP,
    ],
}

# Steps whose FormStepResponse a reviewer is allowed to read. team_details
# and compliance are deliberately excluded - the call manager reads those
# directly in Formbricks.
REVIEWER_VISIBLE_STEPS = {"project_details", "assessment"}


def get_flow(flow_key):
    """Return the ordered list of step dicts for a flow key, or None."""
    return FORM_FLOWS.get(flow_key)


def get_step(flow_key, step_key):
    """Return the step dict matching step_key within a flow, or None."""
    for step in FORM_FLOWS.get(flow_key) or []:
        if step["key"] == step_key:
            return step
    return None


def get_step_by_survey_id(flow_key, survey_id):
    """Return the step dict matching survey_id within a flow, or None."""
    for step in FORM_FLOWS.get(flow_key) or []:
        if step["survey_id"] == survey_id:
            return step
    return None


def get_next_step(flow_key, current_step_key):
    """Return the step dict after current_step_key, or None if it was last."""
    steps = FORM_FLOWS.get(flow_key) or []
    for index, step in enumerate(steps):
        if step["key"] == current_step_key:
            if index + 1 < len(steps):
                return steps[index + 1]
            return None
    return None
