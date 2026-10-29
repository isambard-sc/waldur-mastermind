import copy
import os

import yaml
from django.test import SimpleTestCase

from waldur_mastermind.proposal_forms import flows

EXAMPLE = os.path.join(
    os.path.dirname(flows.__file__), "examples", "airr_form_flows.yaml"
)


def project_step(**overrides):
    step = {
        "key": "project_details",
        "label": "Project details",
        "survey_id": "survey1",
        "reviewer_visible": True,
        "field_map": {"q_title": "name", "q_summary": "project_summary"},
        "resources": {
            "question_id": "q_service",
            "options": [
                {
                    "label": "Isambard-AI",
                    "offering_slug": "isambard-a-1",
                    "attribute_map": {"q_hours": "allocation"},
                }
            ],
        },
    }
    step.update(overrides)
    return step


def team_step(**overrides):
    step = {"key": "team_details", "label": "Team", "survey_id": "survey2"}
    step.update(overrides)
    return step


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
                [s["key"] for s in steps],
                ["project_details", "team_details", "compliance", "assessment"],
            )
            self.assertEqual(
                flows.reviewer_visible_keys(steps), {"project_details", "assessment"}
            )

    def test_normalised_with_defaults(self):
        steps = flows.validate_steps([team_step(label="  Team  ")])
        self.assertEqual(
            steps,
            [
                {
                    "key": "team_details",
                    "label": "Team",
                    "survey_id": "survey2",
                    "reviewer_visible": False,
                    "field_map": {},
                }
            ],
        )

    def test_empty_flow_refused(self):
        self.assertRefused([], "at least one step")
        self.assertRefused({}, "at least one step")

    def test_unknown_key_refused(self):
        # A misspelt key would otherwise be silently ignored.
        self.assertRefused([team_step(feild_map={})], "unknown key(s) feild_map")

    def test_step_key_must_be_a_slug(self):
        self.assertRefused([team_step(key="Team details")], "key must be a slug")

    def test_duplicate_step_key_refused(self):
        self.assertRefused(
            [team_step(), team_step(survey_id="other")], "step keys must be unique"
        )

    def test_duplicate_survey_refused(self):
        self.assertRefused(
            [team_step(), team_step(key="other")], "is used by another step"
        )

    def test_survey_id_must_be_url_safe(self):
        self.assertRefused([team_step(survey_id="a/b")], "survey_id must be")

    def test_label_required(self):
        self.assertRefused([team_step(label="")], "label must be non-empty")

    def test_field_map_only_onto_text_fields(self):
        self.assertRefused(
            [team_step(field_map={"q": "state"})],
            "answers can only be copied onto",
        )

    def test_field_filled_by_two_steps_refused(self):
        self.assertRefused(
            [
                project_step(),
                team_step(field_map={"q_other": "name"}),
            ],
            "'name' is already filled in by step 'project_details'",
        )

    def test_only_one_step_may_choose_resources(self):
        second = copy.deepcopy(project_step())
        second.update(key="more", survey_id="survey3", field_map={})
        self.assertRefused([project_step(), second], "only one step may choose")

    def test_resource_option_labels_and_offerings_unique(self):
        step = project_step()
        option = step["resources"]["options"][0]
        step["resources"]["options"].append(dict(option))
        self.assertRefused([step], "is used twice")

    def test_resources_need_options(self):
        self.assertRefused(
            [project_step(resources={"question_id": "q", "options": []})],
            "options must be a non-empty list",
        )

    def test_navigation(self):
        steps = flows.validate_steps([project_step(), team_step()])
        self.assertEqual(flows.get_step(steps, "team_details")["survey_id"], "survey2")
        self.assertEqual(
            flows.get_step_by_survey_id(steps, "survey1")["key"], "project_details"
        )
        self.assertEqual(
            flows.get_next_step(steps, "project_details")["key"], "team_details"
        )
        self.assertIsNone(flows.get_next_step(steps, "team_details"))
        self.assertIsNone(flows.get_step(steps, "missing"))
        self.assertEqual(flows.offering_slugs(steps), ["isambard-a-1"])
