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
    field_map / integer_field_map / boolean_field_map: (optional)
               {formbricks_question_id: proposal_field_name}, split by the
               type coercion each needs - Formbricks always sends answers as
               strings (or lists of strings for multi-select), regardless of
               the target field's real type:
                 field_map         - used as-is (text fields).
                 integer_field_map - parsed with int().
                 boolean_field_map - "Yes"/"No" (case-insensitive) parsed to
                                      True/False; anything else fails loudly.
               Only present on steps whose answers feed directly into
               Proposal fields - currently only "project_details". Steps
               without these (team_details, compliance, assessment) are
               still snapshotted (see models.FormStepResponse) but are never
               turned into structured Waldur data.
    mapper:    (optional) name of a function in formbricks_mapper.py that
               knows how to apply the field maps plus any step-specific
               logic (e.g. resource selection) to a Proposal.
    resource_question_id / resource_label_to_slug / resource_options:
               (optional, "project_details" only) - see below.
"""

PROJECT_DETAILS_STEP = {
    "key": "project_details",
    "survey_id": "cmt4q1c400004qe01zta9vmnm",
    "field_map": {
        "fjxcnvv5q1ny48q2wazmq2eb": "name",  # "Project title"
        "drihiecfnvzubpjfjc39ai6p": "project_summary",  # "Project summary"
    },
    "integer_field_map": {
        "otdzfok26gyprjg6cttxvas4": "duration_in_days",  # "Project duration, in days"
    },
    "boolean_field_map": {
        # "Does the project involve confidential, sensitive or GDPR-protected information?"
        "cy3gskc7izzurxbrnk4b3mc8": "project_is_confidential",
        # "Is the project non-commercial or research only?" - not a precise
        # match for project_has_civilian_purpose (commercial/non-commercial
        # is a different axis from civilian/military use), but mapped here
        # deliberately per product decision - there's no dedicated field for
        # "non-commercial/research-only" on Proposal.
        "xn6ybk9fk265kjgv37xx0wac": "project_has_civilian_purpose",
    },
    # Multi-select: "AIRR service requested". Formbricks records the
    # selected choice's *label text* as the answer (e.g. "Isambard-AI"), not
    # a stable id or slug - resource_label_to_slug translates that
    # explicitly rather than deriving a slug from the label (e.g.
    # lowercasing it), since offering slugs are real, auto-generated Waldur
    # values free to diverge from Formbricks' label text over time.
    "resource_question_id": "peoi4op1vjaws6c2dvigbahe",
    "resource_label_to_slug": {
        "Isambard-AI": "isambard-a-1",  # real Offering.slug, NOT "isambard-ai"
        # "Zenith" is already a selectable choice on the live survey, but
        # the backing marketplace offering doesn't exist yet (as of
        # 2026-08-26) - deliberately no entry here. Selecting it today is
        # safely skipped (logged as unknown), not a hard failure. Add an
        # entry once the real offering + its RequestedOffering exist on
        # both calls.
    },
    "resource_options": {
        "isambard-a-1": {
            "attribute_field_map": {
                # "GPUh requested" - GPU-*hours*, not a GPU count. Named
                # "allocation" to match waldur_openportal's
                # Resource.options["allocation"] key (see
                # _get_requested_allocation in waldur_openportal/models.py)
                # for forward-compatibility, even though nothing currently
                # bridges RequestedResource.attributes into Resource.options
                # at project-creation time - see formbricks_mapper.py.
                "u3bpmiiaumhqqhjk9yrdet6u": "allocation",
            },
            # Storage isn't assigned by the resource - nothing to default.
            "default_attributes": {},
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
