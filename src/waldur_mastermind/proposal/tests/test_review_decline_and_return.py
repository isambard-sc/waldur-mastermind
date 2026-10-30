import datetime
from unittest import mock

from django.template.loader import render_to_string
from django.utils import timezone
from rest_framework import status

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models, tasks
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests import factories
from waldur_mastermind.proposal.tests.test_return_to_applicant import ReturnTestBase

States = models.Review.States


class ReviewTestBase(ReturnTestBase):
    def setUp(self):
        super().setUp()
        self.reviewer = structure_factories.UserFactory()
        self.review = factories.ReviewFactory(
            proposal=self.proposal, reviewer=self.reviewer, state=States.IN_REVIEW
        )

    def review_url(self, action):
        return f"/api/proposal-reviews/{self.review.uuid.hex}/{action}/"


class DeclineReasonTest(ReviewTestBase):
    def decline(self, **data):
        self.client.force_authenticate(self.reviewer)
        with mock.patch.object(
            tasks.notify_call_managers_about_rejected_review, "delay"
        ) as notify:
            response = self.client.post(self.review_url("reject"), data)
        self.review.refresh_from_db()
        return response, notify

    def test_reason_is_kept_and_sent(self):
        response, notify = self.decline(reason="I collaborate with the applicant.")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(self.review.state, States.REJECTED)
        self.assertEqual(
            self.review.rejection_reason, "I collaborate with the applicant."
        )
        notify.assert_called_once_with(self.review.uuid)

        with mock.patch("waldur_core.core.utils.broadcast_mail") as broadcast:
            tasks.notify_call_managers_about_rejected_review(self.review.uuid)
        context = broadcast.call_args.args[2]
        self.assertEqual(
            context["rejection_reason"], "I collaborate with the applicant."
        )
        for name in ("message.txt", "message.html"):
            text = render_to_string(f"proposal/review_rejected_{name}", context)
            self.assertIn("I collaborate with the applicant.", text)

    def test_reason_is_optional(self):
        response, _ = self.decline()
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(self.review.rejection_reason, "")
        text = render_to_string(
            "proposal/review_rejected_message.txt", {"rejection_reason": ""}
        )
        self.assertNotIn("Reason given", text)


class ReturnToReviewerTest(ReviewTestBase):
    def setUp(self):
        super().setUp()
        self.review.state = States.SUBMITTED
        self.review.summary_private_comment = "Weak methods."
        self.review.save()

    def return_review(self, user=None, reason="Please score the team as well."):
        self.client.force_authenticate(user or self.manager)
        with mock.patch.object(
            tasks.notify_reviewer_about_returned_review, "delay"
        ) as notify:
            with self.captureOnCommitCallbacks(execute=True):
                response = self.client.post(
                    self.review_url("return_to_reviewer"), {"reason": reason}
                )
        self.review.refresh_from_db()
        return response, notify

    def test_call_manager_returns_a_submitted_review(self):
        response, notify = self.return_review()
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(self.review.state, States.IN_REVIEW)
        self.assertEqual(self.review.return_reason, "Please score the team as well.")
        self.assertEqual(self.review.returned_by, self.manager)
        self.assertIsNotNone(self.review.returned_at)
        notify.assert_called_once_with(self.review.uuid.hex)

        # The reviewer can submit it again.
        self.client.force_authenticate(self.reviewer)
        with (
            mock.patch.object(tasks.notify_call_managers_about_new_review, "delay"),
            mock.patch.object(tasks.notify_manager_when_reviews_are_completed, "delay"),
        ):
            response = self.client.post(self.review_url("submit"), {"summary_score": 5})
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

    def test_reviewer_is_told_why(self):
        self.return_review()
        with mock.patch("waldur_core.core.utils.broadcast_mail") as broadcast:
            tasks.notify_reviewer_about_returned_review(self.review.uuid.hex)
        app, event, context, emails = broadcast.call_args.args
        self.assertEqual((app, event), ("proposal", "review_returned"))
        self.assertEqual(emails, [self.reviewer.email])
        for name in ("message.txt", "message.html"):
            text = render_to_string(f"proposal/review_returned_{name}", context)
            self.assertIn("Please score the team as well.", text)

    def test_due_afresh_from_the_return(self):
        self.round.review_duration_in_days = 7
        self.round.save()
        models.Review.objects.filter(pk=self.review.pk).update(
            created=self.review.created - datetime.timedelta(days=30)
        )
        self.return_review()
        self.assertGreater(self.review.review_end_date, timezone.now())
        tasks.expired_reviews_should_be_cancelled()
        self.review.refresh_from_db()
        self.assertEqual(self.review.state, States.IN_REVIEW)

    def test_only_those_who_decide(self):
        response, notify = self.return_review(user=self.reviewer)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(self.review.state, States.SUBMITTED)
        notify.assert_not_called()

    def test_reason_required(self):
        response, _ = self.return_review(reason="")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_only_submitted_reviews_of_undecided_proposals(self):
        self.review.state = States.IN_REVIEW
        self.review.save()
        response, _ = self.return_review()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.review.state = States.SUBMITTED
        self.review.save()
        self.proposal.state = ProposalStates.ACCEPTED
        self.proposal.save()
        response, _ = self.return_review()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_applicants_never_see_the_reasons(self):
        self.return_review()
        self.review.state = States.SUBMITTED
        self.review.rejection_reason = "Earlier decline."
        self.review.save()
        self.call.reviews_visible_to_submitters = True
        self.call.save()
        self.proposal.state = ProposalStates.ACCEPTED
        self.proposal.save()
        self.client.force_authenticate(self.applicant)
        response = self.client.get(f"/api/proposal-reviews/{self.review.uuid.hex}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for field in ("return_reason", "returned_at", "rejection_reason"):
            self.assertNotIn(field, response.data)
