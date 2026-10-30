from rest_framework import test

from waldur_mastermind.proposal import utils
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests import factories, fixtures


class CopySummaryToProjectTest(test.APITransactionTestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.call = self.fixture.round.call

    def allocate(self):
        proposal = factories.ProposalFactory(
            round=self.fixture.round,
            state=ProposalStates.IN_REVIEW,
            project=None,
            project_summary="We will train a model of the sea.",
        )
        utils.allocate_proposal(proposal, approved_by=self.fixture.staff)
        proposal.refresh_from_db()
        return proposal.project

    def test_summary_becomes_the_project_description(self):
        self.call.copy_summary_to_project = True
        self.call.save()
        self.assertEqual(
            self.allocate().description, "We will train a model of the sea."
        )

    def test_upstream_default_leaves_it_empty(self):
        self.assertEqual(self.allocate().description, "")
