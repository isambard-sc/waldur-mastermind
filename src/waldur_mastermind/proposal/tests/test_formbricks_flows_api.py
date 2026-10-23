"""Staff-managed Formbricks flows (FormbricksFlowViewSet).

The flow structure used to be hard-coded in formbricks_flows.py or a mounted
YAML file; these cover managing it over the API instead, including adding a
resource to a flow and having the webhook pick it up.
"""

from unittest import mock

from rest_framework import status, test

from waldur_mastermind.marketplace.tests import factories as marketplace_factories
from waldur_mastermind.proposal import formbricks_client, models
from waldur_mastermind.proposal.enums import (
    FormbricksStepMappers,
    ProposalStates,
    RequestedOfferingStates,
)
from waldur_mastermind.proposal.tests import factories, fixtures
from waldur_mastermind.proposal.tests.test_formbricks import (
    FormbricksTestCase,
    build_payload,
)


def project_details_step(**overrides):
    step = {
        "key": "project_details",
        "survey_id": "survey-project-details",
        "mapper": FormbricksStepMappers.PROJECT_DETAILS,
        "is_reviewer_visible": True,
        "resource_question_id": "q_resources",
        "field_mappings": [
            {"question_id": "q_name", "proposal_field": "name"},
        ],
        "resource_options": [],
    }
    step.update(overrides)
    return step


class FormbricksFlowApiTest(test.APITransactionTestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.offering = marketplace_factories.OfferingFactory()
        self.url = factories.FormbricksFlowFactory.get_list_url()

    def payload(self, **overrides):
        payload = {
            "name": "AIRR-GW",
            "steps": [
                project_details_step(
                    resource_options=[
                        {
                            "choice_label": "Isambard-AI",
                            "offering": self.offering.uuid.hex,
                            "attribute_field_map": {"q_gpus": "allocation"},
                        }
                    ]
                ),
                {"key": "team_details", "survey_id": "survey-team-details"},
            ],
        }
        payload.update(overrides)
        return payload

    def test_staff_can_create_flow_with_steps_and_resources(self):
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.post(self.url, self.payload(), format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        flow = models.FormbricksFlow.objects.get(uuid=response.data["uuid"])
        steps = list(flow.steps.all())
        self.assertEqual(
            [step.key for step in steps], ["project_details", "team_details"]
        )
        self.assertEqual([step.order for step in steps], [0, 1])
        option = steps[0].resource_options.get()
        self.assertEqual(option.offering, self.offering)
        self.assertEqual(option.attribute_field_map, {"q_gpus": "allocation"})
        self.assertEqual(
            response.data["steps"][0]["resource_options"][0]["offering_name"],
            self.offering.name,
        )

    def test_update_replaces_steps(self):
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(self.url, self.payload(), format="json")
        url = factories.FormbricksFlowFactory.get_url(
            models.FormbricksFlow.objects.get(uuid=response.data["uuid"])
        )

        response = self.client.patch(
            url,
            {"steps": [{"key": "compliance", "survey_id": "survey-compliance"}]},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(
            [step["key"] for step in response.data["steps"]], ["compliance"]
        )

    def test_non_staff_cannot_create(self):
        self.client.force_authenticate(self.fixture.user)

        response = self.client.post(self.url, self.payload(), format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authenticated_user_can_list_flows(self):
        factories.FormbricksFlowFactory(name="AIRR-GW")
        self.client.force_authenticate(self.fixture.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([row["name"] for row in response.data], ["AIRR-GW"])

    def test_anonymous_user_is_rejected(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_choices_are_served(self):
        self.client.force_authenticate(self.fixture.user)

        response = self.client.get(
            factories.FormbricksFlowFactory.get_list_url("choices")
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(
            {
                "value": FormbricksStepMappers.PROJECT_DETAILS,
                "label": "Project details",
            },
            response.data["mappers"],
        )
        self.assertIn("name", [c["value"] for c in response.data["proposal_fields"]])

    def assert_rejected(self, payload, field):
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST, response.data
        )
        self.assertIn(field, str(response.data))
        self.assertFalse(models.FormbricksFlow.objects.exists())

    def test_flow_without_steps_is_rejected(self):
        self.assert_rejected(self.payload(steps=[]), "steps")

    def test_duplicate_step_key_is_rejected(self):
        self.assert_rejected(
            self.payload(
                steps=[
                    {"key": "a", "survey_id": "s1"},
                    {"key": "a", "survey_id": "s2"},
                ]
            ),
            "key",
        )

    def test_duplicate_survey_id_is_rejected(self):
        self.assert_rejected(
            self.payload(
                steps=[
                    {"key": "a", "survey_id": "s1"},
                    {"key": "b", "survey_id": "s1"},
                ]
            ),
            "survey_id",
        )

    def test_resource_options_require_resource_question(self):
        self.assert_rejected(
            self.payload(
                steps=[
                    project_details_step(
                        resource_question_id="",
                        resource_options=[
                            {
                                "choice_label": "Isambard-AI",
                                "offering": self.offering.uuid.hex,
                            }
                        ],
                    )
                ]
            ),
            "resource_question_id",
        )

    def test_mappings_require_mapper(self):
        self.assert_rejected(
            self.payload(steps=[project_details_step(mapper="")]), "mapper"
        )

    def test_unknown_mapper_is_rejected(self):
        self.assert_rejected(
            self.payload(steps=[project_details_step(mapper="os_system")]), "mapper"
        )

    def test_unknown_proposal_field_is_rejected(self):
        self.assert_rejected(
            self.payload(
                steps=[
                    project_details_step(
                        field_mappings=[{"question_id": "q", "proposal_field": "state"}]
                    )
                ]
            ),
            "proposal_field",
        )

    def test_same_offering_twice_is_rejected(self):
        option = {"choice_label": "A", "offering": self.offering.uuid.hex}
        self.assert_rejected(
            self.payload(
                steps=[
                    project_details_step(
                        resource_options=[option, {**option, "choice_label": "B"}]
                    )
                ]
            ),
            "offering",
        )

    def test_flow_used_by_a_call_cannot_be_deleted(self):
        flow = factories.FormbricksFlowFactory()
        self.fixture.call.formbricks_flow = flow
        self.fixture.call.save()
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.delete(factories.FormbricksFlowFactory.get_url(flow))

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(models.FormbricksFlow.objects.filter(pk=flow.pk).exists())


class AddResourceToFlowTest(FormbricksTestCase):
    """Adding a resource option in the UI takes effect without a release."""

    @mock.patch.object(formbricks_client, "get_survey", return_value={})
    def test_new_resource_option_is_requested_by_the_webhook(self, mock_get_survey):
        zenith = marketplace_factories.OfferingFactory(customer=self.fixture.customer)
        factories.RequestedOfferingFactory(
            call=self.fixture.call,
            offering=zenith,
            state=RequestedOfferingStates.REQUESTED,
        )
        self.client.force_authenticate(self.fixture.staff)
        url = factories.FormbricksFlowFactory.get_url(self.flow)
        steps = self.client.get(url).json()["steps"]
        steps[0]["resource_options"].append(
            {"choice_label": "Zenith", "offering": zenith.uuid.hex}
        )
        response = self.client.patch(url, {"steps": steps}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.client.force_authenticate(None)

        proposal = factories.ProposalFactory(
            round=self.fixture.round, state=ProposalStates.DRAFT
        )
        answers = {
            "proposal_uuid": str(proposal.uuid),
            "q_name": "My project",
            "q_summary": "Summary",
            "q_resources": ["Zenith"],
        }
        response = self.post_webhook(
            build_payload("survey-project-details", "resp-1", answers)
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        requested_resource = models.RequestedResource.objects.get(proposal=proposal)
        self.assertEqual(requested_resource.requested_offering.offering, zenith)
