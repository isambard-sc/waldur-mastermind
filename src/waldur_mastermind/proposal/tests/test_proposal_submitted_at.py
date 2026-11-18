import datetime
import importlib

from django.apps import apps
from django.test import TestCase
from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models

from . import factories

backfill = importlib.import_module(
    "waldur_mastermind.proposal.migrations.0101_backfill_proposal_submitted_at"
).backfill_submitted_at

MODIFIED = datetime.datetime(2025, 3, 4, 5, 6, 7, tzinfo=datetime.UTC)


class BackfillSubmittedAtTest(TestCase):
    def make(self, state, steps=False, submitted_at=None):
        proposal = factories.ProposalFactory(state=state)
        if steps:
            models.ProposalWorkflowStepInstance.objects.create(
                proposal=proposal, step=1
            )
        models.Proposal.objects.filter(pk=proposal.pk).update(
            modified=MODIFIED, submitted_at=submitted_at
        )
        return proposal

    def submitted_at(self, proposal):
        proposal.refresh_from_db()
        return proposal.submitted_at

    def test_backfills_submitted_proposals_from_last_change(self):
        submitted = self.make(models.Proposal.States.SUBMITTED)
        accepted = self.make(models.Proposal.States.ACCEPTED)
        draft = self.make(models.Proposal.States.DRAFT)
        canceled_draft = self.make(models.Proposal.States.CANCELED)
        canceled_after_submit = self.make(models.Proposal.States.CANCELED, steps=True)
        known = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
        recorded = self.make(models.Proposal.States.IN_REVIEW, submitted_at=known)

        backfill(apps, None)

        self.assertEqual(self.submitted_at(submitted), MODIFIED)
        self.assertEqual(self.submitted_at(accepted), MODIFIED)
        self.assertIsNone(self.submitted_at(draft))
        self.assertIsNone(self.submitted_at(canceled_draft))
        self.assertEqual(self.submitted_at(canceled_after_submit), MODIFIED)
        self.assertEqual(self.submitted_at(recorded), known)


class SubmittedAtInApiTest(test.APITransactionTestCase):
    def test_proposal_reports_submitted_at(self):
        proposal = factories.ProposalFactory(state=models.Proposal.States.SUBMITTED)
        when = datetime.datetime(2026, 2, 3, 4, 5, tzinfo=datetime.UTC)
        models.Proposal.objects.filter(pk=proposal.pk).update(submitted_at=when)

        self.client.force_authenticate(structure_factories.UserFactory(is_staff=True))
        response = self.client.get(factories.ProposalFactory.get_url(proposal))

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["submitted_at"], when)


class SubmittedAtOrderingTest(test.APITransactionTestCase):
    url = "/api/proposal-proposals/"

    def setUp(self):
        call_round = factories.RoundFactory()
        self.proposals = {}
        for name, submitted in (
            ("middle", datetime.datetime(2026, 5, 1, tzinfo=datetime.UTC)),
            ("draft", None),
            ("oldest", datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)),
            ("newest", datetime.datetime(2026, 9, 1, tzinfo=datetime.UTC)),
        ):
            proposal = factories.ProposalFactory(
                round=call_round,
                name=name,
                state=(
                    models.Proposal.States.DRAFT
                    if submitted is None
                    else models.Proposal.States.SUBMITTED
                ),
            )
            models.Proposal.objects.filter(pk=proposal.pk).update(
                submitted_at=submitted
            )
            self.proposals[name] = proposal
        self.client.force_authenticate(structure_factories.UserFactory(is_staff=True))

    def names(self, ordering):
        response = self.client.get(self.url, {"o": ordering})
        self.assertEqual(response.status_code, 200, response.data)
        return [row["name"] for row in response.data]

    def test_oldest_submitted_first_then_drafts(self):
        self.assertEqual(
            self.names("submitted_at"), ["oldest", "middle", "newest", "draft"]
        )

    def test_newest_submitted_first_then_drafts(self):
        self.assertEqual(
            self.names("-submitted_at"), ["newest", "middle", "oldest", "draft"]
        )

    def test_other_orderings_unchanged(self):
        self.assertEqual(
            self.names("slug"),
            [p.name for p in sorted(self.proposals.values(), key=lambda p: p.slug)],
        )

    def test_unknown_ordering_value_behaves_as_before(self):
        response = self.client.get(self.url, {"o": "not_a_field"})
        self.assertEqual(response.status_code, 400)
