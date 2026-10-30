import os

import yaml
from django.test import SimpleTestCase

from waldur_mastermind.proposal_forms import flows

EXAMPLE = os.path.join(
    os.path.dirname(flows.__file__), "examples", "airr_form_flows.yaml"
)


def step(**overrides):
    result = {"key": "team_details", "label": "Team", "survey_id": "survey2"}
    result.update(overrides)
    return result


class ValidateStepsTest(SimpleTestCase):
    def assertRefused(self, steps, message):
        with self.assertRaisesMessage(flows.FlowError, message):
            flows.validate_steps(steps)

    def test_example_flows_are_valid(self):
        with open(EXAMPLE, encoding="utf-8") as f:
            document = yaml.safe_load(f)
        for flow in document["flows"]:
            steps = flows.validate_steps(flow["steps"])
            self.assertEqual(
                flows.reviewer_visible_keys(steps), {"project_details", "assessment"}
            )

    def test_normalised_with_defaults(self):
        self.assertEqual(
            flows.validate_steps([step(label="  Team  ")]),
            [
                {
                    "key": "team_details",
                    "label": "Team",
                    "survey_id": "survey2",
                    "reviewer_visible": False,
                }
            ],
        )

    def test_empty_flow_refused(self):
        self.assertRefused([], "at least one step")
        self.assertRefused({}, "at least one step")

    def test_mapping_is_gone(self):
        # Answers are no longer copied onto the proposal.
        self.assertRefused([step(field_map={})], "unknown key(s) field_map")
        self.assertRefused([step(resources={})], "unknown key(s) resources")

    def test_step_key_must_be_a_slug(self):
        self.assertRefused([step(key="Team details")], "key must be a slug")

    def test_duplicates_refused(self):
        self.assertRefused([step(), step(survey_id="other")], "keys must be unique")
        self.assertRefused([step(), step(key="other")], "is used by another step")

    def test_survey_id_and_label(self):
        self.assertRefused([step(survey_id="a/b")], "survey_id must be")
        self.assertRefused([step(label="")], "label must be non-empty")
        self.assertRefused([step(reviewer_visible="yes")], "true or false")

    def test_get_step(self):
        steps = flows.validate_steps([step()])
        self.assertEqual(flows.get_step(steps, "team_details")["survey_id"], "survey2")
        self.assertIsNone(flows.get_step(steps, "missing"))
