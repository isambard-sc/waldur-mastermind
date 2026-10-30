import datetime
from unittest import mock

from django.utils import timezone
from rest_framework import status, test

from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CallRole, ProposalRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models, tasks, utils, workflow_service
from waldur_mastermind.proposal.enums import CallStates, ProposalStates
from waldur_mastermind.proposal.tests import factories
from waldur_mastermind.proposal.views import validate_round_is_open


class ReturnTestBase(test.APITestCase):
    def setUp(self):
        self.call = factories.CallFactory(state=CallStates.ACTIVE)
        self.round = factories.RoundFactory(
            call=self.call,
            start_time=timezone.now() - datetime.timedelta(days=5),
            cutoff_time=timezone.now() + datetime.timedelta(days=5),
        )
        self.applicant = structure_factories.UserFactory()
        self.proposal = factories.ProposalFactory(
            round=self.round, created_by=self.applicant, state=ProposalStates.DRAFT
        )
        self.proposal.add_user(self.applicant, ProposalRole.MANAGER)
        # Submitted, with its workflow started.
        self.proposal.submitted_at = timezone.now()
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.save()
        workflow_service.create_step_instances(self.proposal)

        self.manager = structure_factories.UserFactory()
        CallRole.MANAGER.add_permission(PermissionEnum.APPROVE_AND_REJECT_PROPOSALS)
        CallRole.MANAGER.add_permission(PermissionEnum.LIST_PROPOSALS)
        self.call.add_user(self.manager, CallRole.MANAGER)

        self.deadline = timezone.now() + datetime.timedelta(days=14)

    def url(self, action):
        return f"/api/proposal-proposals/{self.proposal.uuid.hex}/{action}/"

    def return_it(self, user=None, **data):
        self.client.force_authenticate(user or self.manager)
        payload = {"reason": "Please add your team.", "resubmit_by": self.deadline}
        payload.update(data)
        with mock.patch.object(tasks.notify_team_about_returned_proposal, "delay"):
            return self.client.post(self.url("return_to_applicant"), payload)


class ReturnTest(ReturnTestBase):
    def test_call_manager_returns_proposal(self):
        open_review = factories.ReviewFactory(
            proposal=self.proposal, state=models.Review.States.IN_REVIEW
        )
        done_review = factories.ReviewFactory(
            proposal=self.proposal, state=models.Review.States.SUBMITTED
        )
        self.client.force_authenticate(self.manager)
        with (
            mock.patch.object(
                tasks.notify_team_about_returned_proposal, "delay"
            ) as notify,
            self.captureOnCommitCallbacks(execute=True),
        ):
            response = self.client.post(
                self.url("return_to_applicant"),
                {"reason": "Please add your team.", "resubmit_by": self.deadline},
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["reason"], "Please add your team.")
        self.assertTrue(response.data["is_open"])

        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.state, ProposalStates.DRAFT)
        self.assertIsNone(self.proposal.submitted_at)
        self.assertIsNone(self.proposal.workflow_step)
        self.assertFalse(self.proposal.workflow_step_instances.exists())

        returned = self.proposal.returns.get()
        self.assertEqual(returned.returned_by, self.manager)
        self.assertEqual(returned.previous_state, ProposalStates.IN_REVIEW)
        self.assertTrue(returned.workflow_history)

        # Open reviews are cancelled, not deleted; finished ones are kept.
        open_review.refresh_from_db()
        done_review.refresh_from_db()
        self.assertEqual(open_review.state, models.Review.States.REJECTED)
        self.assertEqual(done_review.state, models.Review.States.SUBMITTED)

        notify.assert_called_once_with(returned.uuid.hex, False)

    def test_only_those_who_decide(self):
        for user in (self.applicant, structure_factories.UserFactory()):
            response = self.return_it(user=user)
            self.assertIn(
                response.status_code,
                (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND),
            )
        staff = structure_factories.UserFactory(is_staff=True)
        self.assertEqual(self.return_it(user=staff).status_code, status.HTTP_200_OK)

    def test_only_undecided_submitted_proposals(self):
        for state in (ProposalStates.DRAFT, ProposalStates.ACCEPTED):
            self.proposal.state = state
            self.proposal.save()
            self.assertEqual(self.return_it().status_code, status.HTTP_400_BAD_REQUEST)
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.decision_held = True
        self.proposal.save()
        response = self.return_it()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("reopen", str(response.data))

    def test_deadline_must_be_in_the_future(self):
        response = self.return_it(
            resubmit_by=timezone.now() - datetime.timedelta(hours=1)
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("resubmit_by", response.data)

    def test_applicant_sees_open_return(self):
        self.return_it()
        self.client.force_authenticate(self.applicant)
        response = self.client.get(f"/api/proposal-proposals/{self.proposal.uuid.hex}/")
        self.assertEqual(
            response.data["open_return"]["reason"], "Please add your team."
        )

        history = self.client.get(self.url("returns")).data
        self.assertEqual(len(history), 1)
        # Internal notes are for those overseeing the call only.
        self.assertIsNone(history[0]["workflow_history"])
        self.client.force_authenticate(self.manager)
        self.assertIsNotNone(
            self.client.get(self.url("returns")).data[0]["workflow_history"]
        )


class ResubmitTest(ReturnTestBase):
    def setUp(self):
        super().setUp()
        self.return_it()
        self.proposal.refresh_from_db()
        # The round closes while the proposal is with its applicant.
        self.round.cutoff_time = timezone.now() - datetime.timedelta(hours=1)
        self.round.save()
        self.proposal.refresh_from_db()

    def test_resubmission_allowed_after_cutoff_until_deadline(self):
        validate_round_is_open(self.proposal)

        self.client.force_authenticate(self.applicant)
        response = self.client.post(self.url("submit"))
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.proposal.refresh_from_db()
        self.assertNotEqual(self.proposal.state, ProposalStates.DRAFT)
        self.assertIsNotNone(self.proposal.submitted_at)
        returned = self.proposal.returns.get()
        self.assertIsNotNone(returned.resubmitted_at)
        self.assertIsNone(models.get_open_return(self.proposal))

    def test_after_the_deadline_until_extended(self):
        models.ProposalReturn.objects.update(
            resubmit_by=timezone.now() - datetime.timedelta(minutes=1)
        )
        self.client.force_authenticate(self.applicant)
        response = self.client.post(self.url("submit"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("extend", str(response.data))
        # Nothing automatic: it stays a draft for the call manager.
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.state, ProposalStates.DRAFT)

        self.client.force_authenticate(self.manager)
        with (
            mock.patch.object(
                tasks.notify_team_about_returned_proposal, "delay"
            ) as notify,
            self.captureOnCommitCallbacks(execute=True),
        ):
            response = self.client.post(
                self.url("extend_return"), {"resubmit_by": self.deadline}
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        notify.assert_called_once_with(response.data["uuid"].replace("-", ""), True)

        self.client.force_authenticate(self.applicant)
        response = self.client.post(self.url("submit"))
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

    def test_extend_needs_an_open_return(self):
        self.proposal.returns.update(resubmitted_at=timezone.now())
        self.client.force_authenticate(self.manager)
        response = self.client.post(
            self.url("extend_return"), {"resubmit_by": self.deadline}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cutoff_sweep_leaves_returned_proposal_alone(self):
        other_draft = factories.ProposalFactory(
            round=self.round, state=ProposalStates.DRAFT
        )
        with mock.patch.object(
            tasks.notify_proposal_creator_about_cancelled_proposal, "apply_async"
        ):
            tasks.proposals_for_ended_rounds_should_be_cancelled()
        self.proposal.refresh_from_db()
        other_draft.refresh_from_db()
        self.assertEqual(self.proposal.state, ProposalStates.DRAFT)
        self.assertEqual(other_draft.state, ProposalStates.CANCELED)

    def test_carry_over_leaves_returned_proposal_alone(self):
        next_round = factories.RoundFactory(
            call=self.call,
            start_time=timezone.now() + datetime.timedelta(days=1),
            cutoff_time=timezone.now() + datetime.timedelta(days=30),
        )
        with mock.patch.object(utils, "next_round_for_drafts", return_value=next_round):
            moved = utils.carry_over_drafts(self.round)
        self.assertNotIn(self.proposal, moved)
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.round, self.round)

    def test_applicant_may_delete_returned_proposal_with_reviews(self):
        factories.ReviewFactory(
            proposal=self.proposal, state=models.Review.States.REJECTED
        )
        self.client.force_authenticate(self.applicant)
        response = self.client.delete(
            f"/api/proposal-proposals/{self.proposal.uuid.hex}/"
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(models.Proposal.objects.filter(pk=self.proposal.pk).exists())


class ReturnNotificationTest(ReturnTestBase):
    def test_team_is_told_why_and_by_when(self):
        returned = utils.return_to_applicant(
            self.proposal, self.manager, "Fix the budget.", self.deadline
        )
        with mock.patch("waldur_core.core.utils.broadcast_mail") as broadcast:
            tasks.notify_team_about_returned_proposal(returned.uuid.hex, False)
        app, event, context, emails = broadcast.call_args.args
        self.assertEqual((app, event), ("proposal", "proposal_returned"))
        self.assertEqual(context["reason"], "Fix the budget.")
        self.assertFalse(context["extended"])
        self.assertEqual(emails, [self.applicant.email])
