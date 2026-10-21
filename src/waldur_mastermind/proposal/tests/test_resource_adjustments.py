"""Call-manager adjustments to a proposal's requested resources, made at the
allocation_decision step - revived bespoke-fork feature, see
models.ProposalResourceAdjustment."""

from django.db import IntegrityError
from django.urls import reverse
from rest_framework import status, test

from waldur_mastermind.proposal import models
from waldur_mastermind.proposal.enums import ProposalStates, RequestedOfferingStates
from waldur_mastermind.proposal.tests import factories, fixtures


def adjustment_detail_url(proposal, adjustment):
    return "http://testserver" + reverse(
        "proposal-proposal-resource_adjustment-detail",
        kwargs={"uuid": proposal.uuid.hex, "obj_uuid": adjustment.uuid.hex},
    )


class ProposalResourceAdjustmentModelTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.requested_resource = self.fixture.requested_resource

    def test_only_one_live_adjustment_per_requested_resource(self):
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.fixture.proposal,
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.MODIFY,
            adjusted_attributes={"cpu": 4},
        )
        with self.assertRaises(IntegrityError):
            models.ProposalResourceAdjustment.objects.create(
                proposal=self.fixture.proposal,
                requested_resource=self.requested_resource,
                action=models.ProposalResourceAdjustment.Actions.REMOVE,
            )

    def test_multiple_add_adjustments_are_not_constrained(self):
        # ADD adjustments have no requested_resource, so the partial unique
        # constraint (condition=requested_resource__isnull=False) does not
        # apply to them - a proposal may have several.
        other_offering = factories.RequestedOfferingFactory(
            call=self.fixture.call, state=RequestedOfferingStates.ACCEPTED
        )
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.fixture.proposal,
            call_offering=self.fixture.requested_offering_accepted,
            action=models.ProposalResourceAdjustment.Actions.ADD,
        )
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.fixture.proposal,
            call_offering=other_offering,
            action=models.ProposalResourceAdjustment.Actions.ADD,
        )
        self.assertEqual(
            self.fixture.proposal.resource_adjustments.filter(
                action=models.ProposalResourceAdjustment.Actions.ADD
            ).count(),
            2,
        )

    def test_get_effective_attributes_for_modify_and_add(self):
        modify = models.ProposalResourceAdjustment(
            action=models.ProposalResourceAdjustment.Actions.MODIFY,
            adjusted_attributes={"cpu": 4},
        )
        add = models.ProposalResourceAdjustment(
            action=models.ProposalResourceAdjustment.Actions.ADD,
            adjusted_attributes={"cpu": 1},
        )
        remove = models.ProposalResourceAdjustment(
            action=models.ProposalResourceAdjustment.Actions.REMOVE
        )
        self.assertEqual(modify.get_effective_attributes(), {"cpu": 4})
        self.assertEqual(add.get_effective_attributes(), {"cpu": 1})
        self.assertEqual(remove.get_effective_attributes(), {})

    def test_get_effective_limits_for_add_has_no_fallback(self):
        # Unlike MODIFY, ADD has no backing requested_resource to fall back
        # to - an added resource with no limits set just gets none.
        add = models.ProposalResourceAdjustment(
            action=models.ProposalResourceAdjustment.Actions.ADD,
            adjusted_limits={},
        )
        self.assertEqual(add.get_effective_limits(), {})

    def test_get_effective_limits_falls_back_to_original_when_empty(self):
        self.requested_resource.limits = {"storage": 100}
        self.requested_resource.save()
        modify_without_limits = models.ProposalResourceAdjustment(
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.MODIFY,
            adjusted_attributes={"cpu": 4},
            adjusted_limits={},
        )
        self.assertEqual(modify_without_limits.get_effective_limits(), {"storage": 100})

    def test_get_effective_limits_uses_adjusted_when_set(self):
        modify_with_limits = models.ProposalResourceAdjustment(
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.MODIFY,
            adjusted_limits={"storage": 500},
        )
        self.assertEqual(modify_with_limits.get_effective_limits(), {"storage": 500})


class ResourceAdjustmentsCreateTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.workflow_step = "allocation_decision"
        self.proposal.save()
        self.requested_resource = self.fixture.requested_resource
        self.url = factories.ProposalFactory.get_url(
            self.proposal, action="resource_adjustments"
        )

    def test_call_manager_can_create_a_modify_adjustment(self):
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.post(
            self.url,
            {
                "requested_resource": self.requested_resource.uuid.hex,
                "action": "modify",
                "adjusted_attributes": {"cpu": 8},
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertTrue(
            models.ProposalResourceAdjustment.objects.filter(
                requested_resource=self.requested_resource, action="modify"
            ).exists()
        )

    def test_call_manager_can_create_a_remove_adjustment(self):
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.post(
            self.url,
            {
                "requested_resource": self.requested_resource.uuid.hex,
                "action": "remove",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)

    def test_call_manager_can_create_an_add_adjustment(self):
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.post(
            self.url,
            {
                "call_offering": self.fixture.requested_offering_accepted.uuid.hex,
                "action": "add",
                "adjusted_attributes": {"cpu": 2},
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)

    def test_add_adjustment_requires_an_accepted_offering(self):
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.post(
            self.url,
            {
                "call_offering": self.fixture.requested_offering.uuid.hex,  # REQUESTED, not ACCEPTED
                "action": "add",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_modify_requires_a_requested_resource(self):
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.post(self.url, {"action": "modify"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_requested_resource_must_belong_to_this_proposal(self):
        other_resource = factories.RequestedResourceFactory()
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.post(
            self.url,
            {"requested_resource": other_resource.uuid.hex, "action": "remove"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_applicant_cannot_create_an_adjustment(self):
        self.client.force_authenticate(self.proposal.created_by)
        response = self.client.post(
            self.url,
            {
                "requested_resource": self.requested_resource.uuid.hex,
                "action": "remove",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_staff_can_create_an_adjustment(self):
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(
            self.url,
            {
                "requested_resource": self.requested_resource.uuid.hex,
                "action": "remove",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)

    def test_rejected_outside_the_allocation_decision_step(self):
        self.proposal.workflow_step = "technical_assessment"
        self.proposal.save()
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.post(
            self.url,
            {
                "requested_resource": self.requested_resource.uuid.hex,
                "action": "remove",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_list_is_gated_the_same_as_create(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.client.force_authenticate(self.proposal.created_by)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class ResourceAdjustmentDetailTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.workflow_step = "allocation_decision"
        self.proposal.save()
        self.requested_resource = self.fixture.requested_resource
        self.adjustment = models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.MODIFY,
            adjusted_attributes={"cpu": 4},
        )
        self.url = adjustment_detail_url(self.proposal, self.adjustment)

    def test_call_manager_can_update_the_adjustment(self):
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.patch(self.url, {"adjusted_attributes": {"cpu": 16}})
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.adjustment.refresh_from_db()
        self.assertEqual(self.adjustment.adjusted_attributes, {"cpu": 16})

    def test_call_manager_can_delete_the_adjustment(self):
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            models.ProposalResourceAdjustment.objects.filter(
                pk=self.adjustment.pk
            ).exists()
        )

    def test_applicant_cannot_delete_the_adjustment(self):
        self.client.force_authenticate(self.proposal.created_by)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_rejected_outside_the_allocation_decision_step(self):
        self.proposal.workflow_step = "technical_assessment"
        self.proposal.save()
        self.client.force_authenticate(self.fixture.call_manager)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_an_adjustment_from_another_proposal_is_not_found(self):
        other_proposal = factories.ProposalFactory(round=self.fixture.round)
        other_proposal.state = ProposalStates.IN_REVIEW
        other_proposal.workflow_step = "allocation_decision"
        other_proposal.save()
        self.client.force_authenticate(self.fixture.call_manager)
        wrong_url = adjustment_detail_url(other_proposal, self.adjustment)
        response = self.client.get(wrong_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class EffectiveAllocationTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.workflow_step = "allocation_decision"
        self.proposal.save()
        self.requested_resource = self.fixture.requested_resource
        self.requested_resource.attributes = {"cpu": 2}
        self.requested_resource.limits = {"storage": 100}
        self.requested_resource.save()
        self.url = factories.ProposalFactory.get_url(
            self.proposal, action="effective_allocation"
        )
        self.client.force_authenticate(self.fixture.call_manager)

    def _row_for(self, data, requested_resource):
        # response.data holds the view's raw Python objects (effective_allocation
        # returns plain dicts, not run through a serializer) -- uuid fields are
        # still uuid.UUID instances here, not yet rendered to strings.
        return next(
            row
            for row in data
            if row["requested_resource_uuid"] == requested_resource.uuid
        )

    def test_unmodified_resource_reports_original_as_effective(self):
        response = self.client.get(self.url)
        row = self._row_for(response.data, self.requested_resource)
        self.assertFalse(row["is_removed"])
        self.assertFalse(row["has_modifications"])
        self.assertEqual(row["effective_attributes"], {"cpu": 2})
        self.assertEqual(row["effective_limits"], {"storage": 100})

    def test_remove_adjustment_is_flagged(self):
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.REMOVE,
        )
        response = self.client.get(self.url)
        row = self._row_for(response.data, self.requested_resource)
        self.assertTrue(row["is_removed"])

    def test_modify_adjustment_reports_adjusted_values(self):
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            requested_resource=self.requested_resource,
            action=models.ProposalResourceAdjustment.Actions.MODIFY,
            adjusted_attributes={"cpu": 8},
        )
        response = self.client.get(self.url)
        row = self._row_for(response.data, self.requested_resource)
        self.assertTrue(row["has_modifications"])
        self.assertEqual(row["effective_attributes"], {"cpu": 8})
        # adjusted_limits left empty -> falls back to original.
        self.assertEqual(row["effective_limits"], {"storage": 100})
        self.assertEqual(row["original_attributes"], {"cpu": 2})

    def test_add_adjustment_appears_as_a_new_row(self):
        other_offering = factories.RequestedOfferingFactory(
            call=self.fixture.call, state=RequestedOfferingStates.ACCEPTED
        )
        models.ProposalResourceAdjustment.objects.create(
            proposal=self.proposal,
            call_offering=other_offering,
            action=models.ProposalResourceAdjustment.Actions.ADD,
            adjusted_attributes={"cpu": 1},
        )
        response = self.client.get(self.url)
        added_rows = [row for row in response.data if row["is_added"]]
        self.assertEqual(len(added_rows), 1)
        self.assertIsNone(added_rows[0]["requested_resource_uuid"])
        self.assertEqual(added_rows[0]["effective_attributes"], {"cpu": 1})
