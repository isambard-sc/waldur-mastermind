"""Whether a call routes applicants through Formbricks, and which flow.

Covers the manager-facing formbricks_flow_key field on ProtectedCallSerializer
(writable, validated against FORM_FLOWS, locked once the call has any
proposal) and the formbricks-flow-keys discovery action it depends on - not
the webhook/survey-mapping machinery itself, which test_formbricks.py covers.
"""

from unittest import mock

from rest_framework import status, test

from waldur_mastermind.proposal import formbricks_flows
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.models import Proposal, Review
from waldur_mastermind.proposal.tests import factories, fixtures

TEST_FORM_FLOWS = {
    "AIRR-GW": [{"key": "project_details", "survey_id": "survey-gw"}],
    "AIRR-RA": [{"key": "project_details", "survey_id": "survey-ra"}],
}


class FormbricksFlowKeySettingTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.call = self.fixture.call
        self.url = factories.CallFactory.get_protected_url(self.call)
        self.client.force_authenticate(self.fixture.staff)
        # The fixture seeds proposals on this round (see ProposalFixture.__init__
        # touching `review`); the lock under test fires on *any* proposal, not
        # just a submitted/in-review one, so start from a clean call. Review
        # has a PROTECT FK to Proposal, so it has to go first.
        Review.objects.filter(proposal__round__call=self.call).delete()
        Proposal.objects.filter(round__call=self.call).delete()

        patcher = mock.patch.object(formbricks_flows, "FORM_FLOWS", TEST_FORM_FLOWS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def patch(self, value):
        return self.client.patch(
            self.url, {"formbricks_flow_key": value}, format="json"
        )

    def test_setting_is_exposed_and_writable(self):
        response = self.client.get(self.url)
        self.assertIsNone(response.data["formbricks_flow_key"])

        response = self.patch("AIRR-GW")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.call.refresh_from_db()
        self.assertEqual(self.call.formbricks_flow_key, "AIRR-GW")

    def test_clearing_the_key_is_allowed(self):
        self.call.formbricks_flow_key = "AIRR-GW"
        self.call.save(update_fields=["formbricks_flow_key"])

        response = self.patch(None)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.call.refresh_from_db()
        self.assertIsNone(self.call.formbricks_flow_key)

    def test_applicants_see_the_setting_on_the_public_call(self):
        self.call.formbricks_flow_key = "AIRR-GW"
        self.call.save(update_fields=["formbricks_flow_key"])
        self.client.force_authenticate(self.fixture.user)
        response = self.client.get(factories.CallFactory.get_public_url(self.call))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["formbricks_flow_key"], "AIRR-GW")

    def test_unconfigured_key_is_rejected(self):
        response = self.patch("not-a-real-flow")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("formbricks_flow_key", response.data)
        self.call.refresh_from_db()
        self.assertIsNone(self.call.formbricks_flow_key)

    def test_change_refused_once_any_proposal_exists(self):
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch("AIRR-GW")

        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST, response.data
        )
        self.assertIn("formbricks_flow_key", response.data)
        self.call.refresh_from_db()
        self.assertIsNone(self.call.formbricks_flow_key)

    def test_clearing_refused_once_any_proposal_exists(self):
        self.call.formbricks_flow_key = "AIRR-GW"
        self.call.save(update_fields=["formbricks_flow_key"])
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch(None)

        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST, response.data
        )
        self.call.refresh_from_db()
        self.assertEqual(self.call.formbricks_flow_key, "AIRR-GW")

    def test_switching_flows_refused_once_any_proposal_exists(self):
        self.call.formbricks_flow_key = "AIRR-GW"
        self.call.save(update_fields=["formbricks_flow_key"])
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch("AIRR-RA")

        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST, response.data
        )
        self.call.refresh_from_db()
        self.assertEqual(self.call.formbricks_flow_key, "AIRR-GW")

    def test_resending_the_current_value_is_not_a_change(self):
        self.call.formbricks_flow_key = "AIRR-GW"
        self.call.save(update_fields=["formbricks_flow_key"])
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch("AIRR-GW")

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)


class FormbricksFlowKeysEndpointTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.url = factories.CallFactory.get_protected_list_url(
            action="formbricks-flow-keys"
        )
        patcher = mock.patch.object(formbricks_flows, "FORM_FLOWS", TEST_FORM_FLOWS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_any_authenticated_user_can_list_configured_keys(self):
        self.client.force_authenticate(self.fixture.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual({row["key"] for row in response.data}, {"AIRR-GW", "AIRR-RA"})

    def test_anonymous_user_is_rejected(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
