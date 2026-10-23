"""Whether a call routes applicants through Formbricks, and which flow.

Covers the manager-facing formbricks_flow field on ProtectedCallSerializer
(writable, locked once the call has any proposal) - not the flow management
API (test_formbricks_flows_api.py) or the webhook/survey-mapping machinery
(test_formbricks.py).
"""

from rest_framework import status, test

from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.models import Proposal, Review
from waldur_mastermind.proposal.tests import factories, fixtures


class FormbricksFlowSettingTest(test.APITestCase):
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

        self.gw_flow = factories.FormbricksFlowFactory(name="AIRR-GW")
        self.ra_flow = factories.FormbricksFlowFactory(name="AIRR-RA")

    def patch(self, flow):
        return self.client.patch(
            self.url,
            {"formbricks_flow": flow.uuid.hex if flow else None},
            format="json",
        )

    def set_flow(self, flow):
        self.call.formbricks_flow = flow
        self.call.save(update_fields=["formbricks_flow"])

    def test_setting_is_exposed_and_writable(self):
        response = self.client.get(self.url)
        self.assertIsNone(response.data["formbricks_flow"])

        response = self.patch(self.gw_flow)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["formbricks_flow_name"], "AIRR-GW")
        self.call.refresh_from_db()
        self.assertEqual(self.call.formbricks_flow, self.gw_flow)

    def test_clearing_the_flow_is_allowed(self):
        self.set_flow(self.gw_flow)

        response = self.patch(None)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.call.refresh_from_db()
        self.assertIsNone(self.call.formbricks_flow)

    def test_applicants_see_the_setting_on_the_public_call(self):
        self.set_flow(self.gw_flow)
        self.client.force_authenticate(self.fixture.user)
        response = self.client.get(factories.CallFactory.get_public_url(self.call))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(str(response.data["formbricks_flow"]), self.gw_flow.uuid.hex)

    def test_unknown_flow_is_rejected(self):
        response = self.client.patch(
            self.url, {"formbricks_flow": "0" * 32}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("formbricks_flow", response.data)
        self.call.refresh_from_db()
        self.assertIsNone(self.call.formbricks_flow)

    def test_change_refused_once_any_proposal_exists(self):
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch(self.gw_flow)

        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST, response.data
        )
        self.assertIn("formbricks_flow", response.data)
        self.call.refresh_from_db()
        self.assertIsNone(self.call.formbricks_flow)

    def test_clearing_refused_once_any_proposal_exists(self):
        self.set_flow(self.gw_flow)
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch(None)

        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST, response.data
        )
        self.call.refresh_from_db()
        self.assertEqual(self.call.formbricks_flow, self.gw_flow)

    def test_switching_flows_refused_once_any_proposal_exists(self):
        self.set_flow(self.gw_flow)
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch(self.ra_flow)

        self.assertEqual(
            response.status_code, status.HTTP_400_BAD_REQUEST, response.data
        )
        self.call.refresh_from_db()
        self.assertEqual(self.call.formbricks_flow, self.gw_flow)

    def test_resending_the_current_value_is_not_a_change(self):
        self.set_flow(self.gw_flow)
        factories.ProposalFactory(round=self.fixture.round, state=ProposalStates.DRAFT)

        response = self.patch(self.gw_flow)

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
