from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import status

from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CallRole, ProposalRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models, tasks
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests import factories
from waldur_mastermind.proposal.tests.test_return_to_applicant import ReturnTestBase


class ReviewImportTest(ReturnTestBase):
    def setUp(self):
        super().setUp()
        CallRole.MANAGER.add_permission(PermissionEnum.MANAGE_PROPOSAL_REVIEW)
        self.proposal.slug = "0251-3191-1538-1"
        self.proposal.save()
        self.other = factories.ProposalFactory(
            round=self.round, state=ProposalStates.SUBMITTED, slug="0251-1420-2104-1"
        )
        self.draft = factories.ProposalFactory(
            round=self.round, state=ProposalStates.DRAFT, slug="0251-0000-0000-1"
        )
        self.londo = structure_factories.UserFactory(email="londo@example.com")
        self.delenn = structure_factories.UserFactory(email="delenn@example.com")
        for reviewer in (self.londo, self.delenn):
            self.call.add_user(reviewer, CallRole.REVIEWER)
        # Distributed peer review: Delenn applied too.
        self.other.add_user(self.delenn, ProposalRole.MEMBER)
        self.outsider = structure_factories.UserFactory(email="vir@example.com")

    def upload(self, text, apply=False, user=None):
        self.client.force_authenticate(user or self.manager)
        with (
            mock.patch.object(
                tasks.notify_reviewer_about_assignment, "delay"
            ) as notify,
            self.captureOnCommitCallbacks(execute=True),
        ):
            response = self.client.post(
                f"/api/proposal-protected-calls/{self.call.uuid.hex}/"
                "import-review-assignments/",
                {
                    "round": self.round.uuid.hex,
                    "file": SimpleUploadedFile(
                        "assignments.csv", text.encode(), content_type="text/csv"
                    ),
                    "apply": apply,
                },
                format="multipart",
            )
        return response, notify

    CSV = (
        "proposal_id,reviewer_email\n"
        "0251-3191-1538-1,Londo@example.com\n"
        "0251-1420-2104-1,londo@example.com\n"
        "0251-3191-1538-1,londo@example.com\n"
        "0251-1420-2104-1,delenn@example.com\n"
        "0251-0000-0000-1,londo@example.com\n"
        "0251-9999-9999-1,londo@example.com\n"
        "0251-3191-1538-1,vir@example.com\n"
    )

    def statuses(self, response):
        return [(row["status"], row["detail"]) for row in response.data]

    def test_dry_run_reports_every_row_and_creates_nothing(self):
        response, notify = self.upload(self.CSV)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(
            self.statuses(response),
            [
                ("ready", ""),
                ("ready", ""),
                ("skipped", "Already assigned."),
                ("error", "The reviewer is on this proposal's team."),
                ("error", "The proposal is not submitted or in review."),
                ("error", "Proposal not found in this round."),
                ("error", "No reviewer of this call has this email."),
            ],
        )
        self.assertEqual(response.data[0]["proposal_name"], self.proposal.name)
        self.assertFalse(models.Review.objects.exists())
        notify.assert_not_called()

    def test_apply_creates_the_valid_reviews(self):
        response, notify = self.upload(self.CSV, apply=True)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(
            [row["status"] for row in response.data][:2], ["created", "created"]
        )
        reviews = models.Review.objects.filter(reviewer=self.londo)
        self.assertEqual(
            set(reviews.values_list("proposal_id", flat=True)),
            {self.proposal.id, self.other.id},
        )
        self.assertEqual(notify.call_count, 2)

        # Uploading the same file again assigns nothing twice.
        response, notify = self.upload(self.CSV, apply=True)
        self.assertEqual(response.data[0]["status"], "skipped")
        self.assertEqual(models.Review.objects.count(), 2)

    def test_only_those_who_manage_reviews(self):
        response, _ = self.upload(self.CSV, apply=True, user=self.londo)
        self.assertIn(response.status_code, (403, 404))
        self.assertFalse(models.Review.objects.exists())

    def test_columns_are_found_by_name(self):
        response, _ = self.upload(
            "Reviewer Email,Proposal ID\nlondo@example.com,0251-3191-1538-1\n"
        )
        self.assertEqual(self.statuses(response), [("ready", "")])
        response, _ = self.upload("name,email\nx,y\n")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
