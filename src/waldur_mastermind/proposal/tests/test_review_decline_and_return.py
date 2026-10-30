from unittest import mock

from django.template.loader import render_to_string
from rest_framework import status

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models, tasks
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
