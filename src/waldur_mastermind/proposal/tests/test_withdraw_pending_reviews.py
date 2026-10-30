from unittest import mock

from waldur_mastermind.proposal import models, tasks
from waldur_mastermind.proposal.enums import (
    AssignmentBatchStatuses,
    AssignmentItemStatuses,
    ProposalStates,
)
from waldur_mastermind.proposal.tests import factories
from waldur_mastermind.proposal.tests.test_return_to_applicant import ReturnTestBase

States = models.Review.States


class WithdrawPendingReviewsTest(ReturnTestBase):
    def setUp(self):
        super().setUp()
        self.call.withdraw_pending_reviews = True
        self.call.save()
        self.unfinished = factories.ReviewFactory(
            proposal=self.proposal, state=States.IN_REVIEW
        )
        self.submitted = factories.ReviewFactory(
            proposal=self.proposal, state=States.SUBMITTED
        )
        self.batch = factories.AssignmentBatchFactory(
            call=self.call, status=AssignmentBatchStatuses.SENT
        )
        self.request = factories.AssignmentItemFactory(
            batch=self.batch, proposal=self.proposal
        )
        self.accepted = factories.AssignmentItemFactory(
            batch=factories.AssignmentBatchFactory(
                call=self.call, status=AssignmentBatchStatuses.RESPONDED
            ),
            proposal=self.proposal,
            status=AssignmentItemStatuses.ACCEPTED,
            review=self.unfinished,
        )

    def decide(self, state):
        self.proposal.state = state
        self.proposal.save()

    def assert_withdrawn(self):
        self.assertFalse(models.Review.objects.filter(pk=self.unfinished.pk).exists())
        self.assertTrue(models.Review.objects.filter(pk=self.submitted.pk).exists())
        self.assertFalse(
            models.AssignmentItem.objects.filter(
                pk__in=[self.request.pk, self.accepted.pk]
            ).exists()
        )

    def test_withdrawn_when_decided(self):
        for state in (
            ProposalStates.ACCEPTED,
            ProposalStates.REJECTED,
            ProposalStates.CANCELED,
        ):
            with self.subTest(state=state):
                self.setUp()
                self.decide(state)
                self.assert_withdrawn()
                # Its only items gone, the batch goes too.
                self.assertFalse(
                    models.AssignmentBatch.objects.filter(pk=self.batch.pk).exists()
                )

    def test_batch_with_other_proposals_is_kept_and_answered(self):
        other = factories.AssignmentItemFactory(
            batch=self.batch, status=AssignmentItemStatuses.DECLINED
        )
        self.decide(ProposalStates.REJECTED)
        self.batch.refresh_from_db()
        self.assertEqual(self.batch.status, AssignmentBatchStatuses.RESPONDED)
        self.assertTrue(models.AssignmentItem.objects.filter(pk=other.pk).exists())

    def test_withdrawn_when_returned_to_applicant(self):
        response = self.return_it()
        self.assertEqual(response.status_code, 200, response.data)
        self.assert_withdrawn()

    def test_upstream_default_leaves_them(self):
        self.call.withdraw_pending_reviews = False
        self.call.save()
        self.decide(ProposalStates.ACCEPTED)
        self.unfinished.refresh_from_db()
        self.assertEqual(self.unfinished.state, States.IN_REVIEW)
        self.assertTrue(
            models.AssignmentItem.objects.filter(pk=self.request.pk).exists()
        )

        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.save()
        with mock.patch.object(tasks.notify_team_about_returned_proposal, "delay"):
            self.return_it()
        self.unfinished.refresh_from_db()
        self.assertEqual(self.unfinished.state, States.REJECTED)

    def test_other_state_changes_leave_them(self):
        self.decide(ProposalStates.SUBMITTED)
        self.assertTrue(models.Review.objects.filter(pk=self.unfinished.pk).exists())
