from rest_framework import test

from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.notifications import models
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.models import Review
from waldur_mastermind.proposal.tests import factories as proposal_factories


class RoundBroadcastTest(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.round = proposal_factories.RoundFactory()
        self.drafter = structure_factories.UserFactory()
        self.draft = proposal_factories.ProposalFactory(
            round=self.round, state=ProposalStates.DRAFT, created_by=self.drafter
        )
        self.colleague = structure_factories.UserFactory()
        self.draft.add_user(self.colleague, ProposalRole.MEMBER)

        self.submitter = structure_factories.UserFactory()
        self.submitted = proposal_factories.ProposalFactory(
            round=self.round, state=ProposalStates.SUBMITTED, created_by=self.submitter
        )
        self.reviewer = structure_factories.UserFactory()
        proposal_factories.ReviewFactory(
            proposal=self.submitted,
            reviewer=self.reviewer,
            state=Review.States.IN_REVIEW,
        )
        self.declined = structure_factories.UserFactory()
        proposal_factories.ReviewFactory(
            proposal=self.submitted,
            reviewer=self.declined,
            state=Review.States.REJECTED,
        )
        # Someone else's round.
        proposal_factories.ProposalFactory(state=ProposalStates.DRAFT)
        self.client.force_authenticate(self.staff)

    def recipients(self, **query):
        response = self.client.get(
            "/api/broadcast-messages/recipients/",
            {"rounds": self.round.uuid.hex, **query},
        )
        self.assertEqual(response.status_code, 200, response.data)
        return {row["email"] for row in response.data}

    def test_teams_still_in_draft(self):
        self.assertEqual(
            self.recipients(proposal_states="draft"),
            {self.drafter.email, self.colleague.email},
        )

    def test_every_team_in_the_round(self):
        self.assertEqual(
            self.recipients(),
            {self.drafter.email, self.colleague.email, self.submitter.email},
        )

    def test_reviewers_only(self):
        self.assertEqual(
            self.recipients(proposal_teams="false", reviewers="true"),
            {self.reviewer.email},
        )

    def test_broadcast_records_its_audience(self):
        response = self.client.post(
            "/api/broadcast-messages/",
            {
                "subject": "Submit soon",
                "body": "The round closes on Friday.",
                "query": {
                    "rounds": [self.round.uuid.hex],
                    "proposal_states": ["draft"],
                },
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        message = models.BroadcastMessage.objects.get(uuid=response.data["uuid"])
        self.assertEqual(
            set(message.emails), {self.drafter.email, self.colleague.email}
        )
        self.assertEqual(message.query["proposal_states"], ["draft"])
        self.assertEqual(message.query["rounds"][0]["uuid"], self.round.uuid.hex)
