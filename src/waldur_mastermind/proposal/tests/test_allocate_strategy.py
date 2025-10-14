import datetime

from ddt import data, ddt
from rest_framework import status, test

from waldur_core.permissions.fixtures import ProjectRole, ProposalRole
from waldur_core.permissions.utils import has_user
from waldur_core.structure.tests.factories import UserFactory
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.proposal import models
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests import fixtures

from . import factories


@ddt
class ManualApproveTest(test.APITransactionTestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        self.approve_url = factories.ProposalFactory.get_url(self.proposal, "approve")
        self.reject_url = factories.ProposalFactory.get_url(self.proposal, "reject")

    @data(
        "staff",
        "call_manager",
    )
    def test_user_can_approve_proposal(self, user):
        user = getattr(self.fixture, user)
        self.client.force_authenticate(user)
        response = self.client.post(self.approve_url, {"allocation_comment": "done"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.state, ProposalStates.ACCEPTED)
        self.assertEqual(self.proposal.allocation_comment, "done")
        self.assertTrue(self.proposal.requestedresource_set.first().resource)
        resource = self.proposal.requestedresource_set.first().resource
        self.assertTrue(
            marketplace_models.Order.objects.filter(resource=resource).exists()
        )

    def _check_membership(self, proposal_role, project_role=None) -> bool:
        user = UserFactory()
        self.proposal.add_user(user, proposal_role)
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(self.approve_url, {"allocation_comment": "done"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.proposal.refresh_from_db()

        return has_user(self.proposal.project, user, project_role)

    def test_when_proposal_approved_users_are_added_to_the_project(self):
        project_role = ProjectRole.MEMBER
        proposal_role = ProposalRole.MEMBER
        models.ProposalProjectRoleMapping.objects.create(
            call=self.fixture.call,
            project_role=project_role,
            proposal_role=proposal_role,
        )
        result = self._check_membership(proposal_role, project_role)
        self.assertTrue(result)

    def test_unmapped_roles_are_not_added_to_the_project(self):
        models.ProposalProjectRoleMapping.objects.create(
            call=self.fixture.call,
            proposal_role=ProposalRole.MANAGER,
        )
        result = self._check_membership(ProposalRole.MANAGER)
        self.assertFalse(result)

    @data(
        "proposal_creator",
    )
    def test_user_can_not_approve_proposal(self, user):
        user = getattr(self.fixture, user)
        self.client.force_authenticate(user)
        response = self.client.post(self.approve_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @data(
        "owner",
        "customer_support",
    )
    def test_customer_user_can_not_approve_proposal(self, user):
        user = getattr(self.fixture, user)
        self.client.force_authenticate(user)
        response = self.client.post(self.approve_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @data(
        "staff",
        "call_manager",
    )
    def test_user_can_reject_proposal(self, user):
        user = getattr(self.fixture, user)
        self.client.force_authenticate(user)
        response = self.client.post(self.reject_url, {"allocation_comment": "done"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.state, ProposalStates.REJECTED)
        self.assertEqual(self.proposal.allocation_comment, "done")

    @data(
        "proposal_creator",
    )
    def test_user_can_not_reject_proposal(self, user):
        user = getattr(self.fixture, user)
        self.client.force_authenticate(user)
        response = self.client.post(self.reject_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


@ddt
class ProjectEndDateTest(test.APITransactionTestCase):
    """Tests for automatic project end_date setting based on duration."""

    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        self.approve_url = factories.ProposalFactory.get_url(self.proposal, "approve")

    def test_end_date_set_from_proposal_duration_in_days(self):
        """Test that project end_date is set from proposal.duration_in_days."""
        # Set up: proposal with duration and fixed allocation date
        self.proposal.duration_in_days = 365
        self.proposal.save()

        # Set fixed allocation date on round
        allocation_date = datetime.date(2025, 1, 1)
        self.proposal.round.allocation_time = models.Round.AllocationTimes.FIXED_DATE
        self.proposal.round.allocation_date = allocation_date
        self.proposal.round.save()

        # Approve proposal
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(
            self.approve_url, {"allocation_comment": "approved"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify project dates
        self.proposal.refresh_from_db()
        project = self.proposal.project
        self.assertIsNotNone(project)
        self.assertEqual(project.start_date, allocation_date)
        expected_end_date = allocation_date + datetime.timedelta(days=365)
        self.assertEqual(project.end_date, expected_end_date)

    def test_end_date_set_from_call_fixed_duration_in_days(self):
        """Test that project end_date uses call.fixed_duration_in_days."""
        # Set up: call with fixed duration takes precedence
        self.fixture.call.fixed_duration_in_days = 180
        self.fixture.call.save()

        self.proposal.duration_in_days = 365  # Should be ignored
        self.proposal.save()

        # Set fixed allocation date on round
        allocation_date = datetime.date(2025, 6, 1)
        self.proposal.round.allocation_time = models.Round.AllocationTimes.FIXED_DATE
        self.proposal.round.allocation_date = allocation_date
        self.proposal.round.save()

        # Approve proposal
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(
            self.approve_url, {"allocation_comment": "approved"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify call duration takes precedence
        self.proposal.refresh_from_db()
        project = self.proposal.project
        self.assertIsNotNone(project)
        self.assertEqual(project.start_date, allocation_date)
        expected_end_date = allocation_date + datetime.timedelta(days=180)
        self.assertEqual(project.end_date, expected_end_date)

    def test_end_date_not_set_without_start_date(self):
        """Test that end_date is not set if start_date is not set."""
        # Set duration but no fixed allocation date
        self.proposal.duration_in_days = 365
        self.proposal.save()

        # Don't set fixed allocation date (use ON_DECISION)
        self.proposal.round.allocation_time = models.Round.AllocationTimes.ON_DECISION
        self.proposal.round.save()

        # Approve proposal
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(
            self.approve_url, {"allocation_comment": "approved"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify no end_date is set
        self.proposal.refresh_from_db()
        project = self.proposal.project
        self.assertIsNotNone(project)
        self.assertIsNone(project.start_date)
        self.assertIsNone(project.end_date)

    def test_end_date_not_set_without_duration(self):
        """Test that end_date is not set if no duration is specified."""
        # Set allocation date but no duration
        allocation_date = datetime.date(2025, 3, 1)
        self.proposal.round.allocation_time = models.Round.AllocationTimes.FIXED_DATE
        self.proposal.round.allocation_date = allocation_date
        self.proposal.round.save()

        # No duration set on proposal or call
        self.proposal.duration_in_days = None
        self.proposal.save()

        # Approve proposal
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(
            self.approve_url, {"allocation_comment": "approved"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify end_date is not set
        self.proposal.refresh_from_db()
        project = self.proposal.project
        self.assertIsNotNone(project)
        self.assertEqual(project.start_date, allocation_date)
        self.assertIsNone(project.end_date)

    def test_project_description_copied_from_proposal_summary(self):
        """Test that project description is copied from proposal summary."""
        # Set up proposal with project summary
        test_summary = "This is a research project on quantum computing."
        self.proposal.project_summary = test_summary
        self.proposal.save()

        # Set fixed allocation date
        allocation_date = datetime.date(2025, 4, 1)
        self.proposal.round.allocation_time = (
            models.Round.AllocationTimes.FIXED_DATE
        )
        self.proposal.round.allocation_date = allocation_date
        self.proposal.round.save()

        # Approve proposal
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(
            self.approve_url, {"allocation_comment": "approved"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify project description is copied from proposal summary
        self.proposal.refresh_from_db()
        project = self.proposal.project
        self.assertIsNotNone(project)
        self.assertEqual(project.description, test_summary)
