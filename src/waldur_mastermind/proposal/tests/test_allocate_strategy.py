import datetime
from unittest import mock

from django.utils import timezone
from rest_framework import test

from waldur_core.permissions.fixtures import ProjectRole, ProposalRole
from waldur_core.permissions.utils import has_user
from waldur_core.structure.models import Project
from waldur_core.structure.tests.factories import UserFactory
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace.enums import SUPPORT_OFFERING, OrderStates
from waldur_mastermind.proposal import models, utils
from waldur_mastermind.proposal.enums import (
    AllocationTimes,
    ProposalStates,
    RequestedOfferingStates,
)
from waldur_mastermind.proposal.tests import factories, fixtures


# The legacy one-click approve/reject endpoints were removed; the workflow
# engine is the single decision path (see test_workflow.py). These tests cover
# allocate_proposal — the shared provisioning routine both the workflow terminal
# and (historically) the legacy Accept relied on — directly.
class AllocateProposalTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.project = None
        self.proposal.save()

    def test_allocation_provisions_project_resource_and_order(self):
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.proposal.refresh_from_db()

        self.assertIsNotNone(self.proposal.project)
        self.assertEqual(self.proposal.approved_by, self.fixture.staff)
        resource = self.proposal.requestedresource_set.first().resource
        self.assertTrue(resource)
        self.assertTrue(
            marketplace_models.Order.objects.filter(resource=resource).exists()
        )

    def test_allocation_is_idempotent(self):
        # Re-allocating an already-provisioned proposal must NOT create a second
        # project / resource / order (the core F6.7 correctness guard).
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.proposal.refresh_from_db()
        project = self.proposal.project
        resource = self.proposal.requestedresource_set.first().resource
        order_count = marketplace_models.Order.objects.filter(resource=resource).count()
        project_count = Project.available_objects.count()

        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.proposal.refresh_from_db()

        self.assertEqual(self.proposal.project, project)
        self.assertEqual(Project.available_objects.count(), project_count)
        self.assertEqual(
            marketplace_models.Order.objects.filter(resource=resource).count(),
            order_count,
        )

    def _allocate_and_check_membership(self, proposal_role, project_role=None) -> bool:
        user = UserFactory()
        self.proposal.add_user(user, proposal_role)
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.proposal.refresh_from_db()
        return has_user(self.proposal.project, user, project_role)

    def test_mapped_roles_are_added_to_the_project_on_allocation(self):
        models.ProposalProjectRoleMapping.objects.create(
            call=self.fixture.call,
            project_role=ProjectRole.MEMBER,
            proposal_role=ProposalRole.MEMBER,
        )
        self.assertTrue(
            self._allocate_and_check_membership(ProposalRole.MEMBER, ProjectRole.MEMBER)
        )

    def test_unmapped_roles_are_not_added_to_the_project_on_allocation(self):
        models.ProposalProjectRoleMapping.objects.create(
            call=self.fixture.call,
            proposal_role=ProposalRole.MANAGER,
        )
        self.assertFalse(self._allocate_and_check_membership(ProposalRole.MANAGER))


class AllocateProposalResourceAdjustmentTest(test.APITestCase):
    """allocate_proposal is the one place a resource adjustment has a real
    side effect, not just a preview - see models.ProposalResourceAdjustment."""

    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.project = None
        self.proposal.save()
        self.requested_resource = self.fixture.requested_resource

    def test_remove_adjustment_skips_resource_and_order_creation(self):
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.REMOVE,
        )
        original_resource = self.requested_resource.resource
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.requested_resource.refresh_from_db()

        # Untouched: the factory-assigned stand-in resource (not a real
        # allocation result) stays exactly as it was, since the REMOVE
        # branch never writes requested_resource.resource at all.
        self.assertEqual(self.requested_resource.resource, original_resource)
        self.assertFalse(
            marketplace_models.Resource.objects.filter(
                project=self.proposal.project
            ).exists()
        )
        self.assertFalse(
            marketplace_models.Order.objects.filter(
                resource__project=self.proposal.project
            ).exists()
        )

    def test_remove_adjustment_does_not_consume_an_offering_index_slot(self):
        # A second request for the same offering as the removed one must be
        # named as if it were the only one of its kind, not "(2)".
        other_resource = factories.RequestedResourceFactory(
            proposal=self.proposal,
            requested_offering=self.fixture.requested_offering_accepted,
        )
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.REMOVE,
        )
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        other_resource.refresh_from_db()

        offering_name = self.fixture.requested_offering_accepted.offering.name
        self.assertNotIn(f"{offering_name} (2)", other_resource.resource.name)
        self.assertIn(offering_name, other_resource.resource.name)

    def test_modify_adjustment_uses_adjusted_attributes_and_limits(self):
        self.requested_resource.attributes = {"cpu": 2}
        self.requested_resource.limits = {"storage": 100}
        self.requested_resource.save()
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.MODIFY,
            adjusted_attributes={"cpu": 8},
        )
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.requested_resource.refresh_from_db()

        self.assertEqual(self.requested_resource.resource.attributes, {"cpu": 8})
        # adjusted_limits left empty -> falls back to the original limits
        # (decision 2: the UI only lets a manager edit attributes).
        self.assertEqual(self.requested_resource.resource.limits, {"storage": 100})

    def test_add_adjustment_creates_a_new_resource_and_order(self):
        other_offering = factories.RequestedOfferingFactory(
            call=self.fixture.call, state=RequestedOfferingStates.ACCEPTED
        )
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            call_offering=other_offering,
            action=models.ProposalResourceAdjustment.Actions.ADD,
            adjusted_attributes={"cpu": 1},
        )
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.proposal.refresh_from_db()

        added_resource = marketplace_models.Resource.objects.get(
            project=self.proposal.project, offering=other_offering.offering
        )
        self.assertEqual(added_resource.attributes, {"cpu": 1})
        self.assertTrue(
            marketplace_models.Order.objects.filter(resource=added_resource).exists()
        )

    def test_add_adjustment_for_same_offering_as_a_regular_request_is_deduplicated(
        self,
    ):
        # Both the regular request and the added resource target the same
        # offering - both must be numbered (1)/(2), neither left bare.
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            call_offering=self.fixture.requested_offering_accepted,
            action=models.ProposalResourceAdjustment.Actions.ADD,
            adjusted_attributes={"cpu": 1},
        )
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.requested_resource.refresh_from_db()

        offering = self.fixture.requested_offering_accepted.offering
        resources = marketplace_models.Resource.objects.filter(
            project=self.proposal.project, offering=offering
        )
        self.assertEqual(resources.count(), 2)
        names = set(resources.values_list("name", flat=True))
        self.assertTrue(any(name.endswith(f"{offering.name} (1)") for name in names))
        self.assertTrue(any(name.endswith(f"{offering.name} (2)") for name in names))


class AllocatedOrderApprovalTest(test.APITestCase):
    """The consumer step must be approved exactly once.

    Regression for #422: allocate_proposal ran its own consumer approval on top
    of the one notify_approvers_when_order_is_created already performs for the
    orders it places. Every earlier test here used the fixture's Basic
    offering, the one type whose provider review parks the order short of
    EXECUTING, which is why the crash went unnoticed.
    """

    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.project = None
        self.proposal.save()

    def _order(self):
        self.proposal.refresh_from_db()
        resource = self.proposal.requestedresource_set.first().resource
        return marketplace_models.Order.objects.get(resource=resource)

    def _use_offering_type(self, offering_type):
        offering = self.fixture.offering
        offering.type = offering_type
        offering.save(update_fields=["type"])

    def test_order_reaches_executing_when_provider_review_is_skipped(self):
        # Support.OfferingTemplate falls through to the catch-all in
        # order_should_not_be_reviewed_by_provider, so creation takes the order
        # all the way to EXECUTING. Re-approving there used to raise
        # TransitionNotAllowed and surface as a 500 on complete_workflow_step.
        self._use_offering_type(SUPPORT_OFFERING)

        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)

        order = self._order()
        self.assertEqual(order.state, OrderStates.EXECUTING)
        # Whoever accepted the proposal is the consumer-side decision, not the
        # robot whose staff flag used to stand in for one.
        self.assertEqual(order.consumer_reviewed_by, self.fixture.staff)
        self.assertIsNotNone(order.consumer_reviewed_at)

    @mock.patch("waldur_mastermind.marketplace.tasks.process_order")
    def test_provider_reviewed_order_is_notified_once(self, mock_process_order):
        # The Basic path never crashed, but the second approval re-entered the
        # PENDING_PROVIDER branch and queued a duplicate provider mail.
        with mock.patch(
            "waldur_mastermind.marketplace.tasks.notify_provider_about_pending_order"
        ) as mock_notify:
            with self.captureOnCommitCallbacks(execute=True):
                utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)

        order = self._order()
        self.assertEqual(order.state, OrderStates.PENDING_PROVIDER)
        self.assertEqual(mock_notify.delay.call_count, 1)
        mock_process_order.delay.assert_not_called()

    def test_future_dated_project_keeps_the_order_pending(self):
        # The guard must not swallow the PENDING_PROJECT route, which creation
        # reaches before either provider check.
        self._use_offering_type(SUPPORT_OFFERING)
        self.proposal.round.allocation_date = timezone.now() + datetime.timedelta(
            weeks=1
        )
        self.proposal.round.save()
        models.CallWorkflowStep.objects.update_or_create(
            call=self.proposal.round.call,
            step="allocation_decision",
            defaults={"allocation_time": AllocationTimes.FIXED_DATE},
        )

        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)

        self.assertEqual(self._order().state, OrderStates.PENDING_PROJECT)
