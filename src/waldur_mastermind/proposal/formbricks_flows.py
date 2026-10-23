"""Lookups over a call's Formbricks flow.

A flow (models.FormbricksFlow) is an ordered list of steps
(models.FormbricksFlowStep), each one Formbricks survey an applicant fills
in. Flows are managed by staff in the UI (FormbricksFlowViewSet) and picked
per call (Call.formbricks_flow).

Step fields:
    key:       stable identifier for this step within the flow, e.g.
               "project_details". Used to look up the next step and stored on
               FormStepResponse.step_key.
    survey_id: the Formbricks survey ID for this step.
    mapper:    (optional) one of enums.FormbricksStepMappers - the
               formbricks_mapper.py handler that applies the step's field
               mappings and resource options to a Proposal. Steps without one
               are only snapshotted (models.FormStepResponse).
    is_reviewer_visible: whether reviewers may read the step's answers.
    field_mappings: {question_id -> Proposal field, value type}. Formbricks
               always sends answers as strings, so value_type says how to
               coerce them (text, integer, or Yes/No boolean).
    resource_question_id / resource_options: the step's resource
               multi-select. Formbricks records the selected choice's label
               text, so each option maps a label to a marketplace offering.
"""


def get_steps(flow):
    """Return the flow's steps in order, or an empty list for no flow."""
    if flow is None:
        return []
    return list(flow.steps.all())


def get_step(flow, step_key):
    """Return the step matching step_key within a flow, or None."""
    for step in get_steps(flow):
        if step.key == step_key:
            return step
    return None


def get_step_by_survey_id(flow, survey_id):
    """Return the step matching survey_id within a flow, or None."""
    for step in get_steps(flow):
        if step.survey_id == survey_id:
            return step
    return None


def get_next_step(flow, current_step_key):
    """Return the step after current_step_key, or None if it was last."""
    steps = get_steps(flow)
    for index, step in enumerate(steps):
        if step.key == current_step_key:
            if index + 1 < len(steps):
                return steps[index + 1]
            return None
    return None


def get_reviewer_visible_step_keys(flow):
    """Return the keys of the steps whose answers reviewers may read."""
    return {step.key for step in get_steps(flow) if step.is_reviewer_visible}
