"""The orders a proposal's award places carry their resource's name.

A backend that creates its resource from the order reads the name from the
order's attributes, as for an order placed through the API. Award orders had
none, so OpenPortal allocations were left Errored. A name given in the
request is kept; otherwise the order takes the name the award gives the
resource (see test_allocated_resource_names).
"""

from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace.tests import factories as marketplace_factories
from waldur_mastermind.marketplace_openportal import PLUGIN_NAME
from waldur_mastermind.marketplace_openportal.processor import (
    CreateAllocationProcessor,
)
from waldur_mastermind.proposal import utils
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests import factories, fixtures


class AllocatedOrderNameTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.proposal.state = ProposalStates.IN_REVIEW
        self.proposal.project = None
        self.proposal.save()

    def request(self, offering, **kwargs):
        return factories.RequestedResourceFactory(
            proposal=self.proposal,
            requested_offering=factories.RequestedOfferingFactory(
                call=self.fixture.call, offering=offering
            ),
            resource=None,
            **kwargs,
        )

    def allocate(self):
        utils.allocate_proposal(self.proposal, approved_by=self.fixture.staff)
        self.proposal.refresh_from_db()
        return {
            requested.uuid: marketplace_models.Order.objects.get(
                resource=requested.resource
            )
            for requested in self.proposal.requestedresource_set.all()
        }

    def test_the_order_is_named_as_its_resource(self):
        requested = self.request(marketplace_factories.OfferingFactory(name="HPC"))

        order = self.allocate()[requested.uuid]

        self.assertEqual(order.attributes["name"], order.resource.name)
        self.assertEqual(
            order.attributes["name"], f"{self.proposal.project.name} - HPC"
        )

    def test_repeated_offerings_are_named_apart(self):
        offering = marketplace_factories.OfferingFactory(name="HPC")
        first, second = self.request(offering), self.request(offering)

        orders = self.allocate()

        self.assertNotEqual(
            orders[first.uuid].attributes["name"],
            orders[second.uuid].attributes["name"],
        )

    def test_a_name_given_in_the_request_is_kept(self):
        """In the order's attributes, as upstream always kept it; the
        resource is still named after its project and offering."""
        requested = self.request(
            marketplace_factories.OfferingFactory(name="HPC"),
            attributes={"name": "Our cluster time"},
        )

        order = self.allocate()[requested.uuid]

        self.assertEqual(order.attributes["name"], "Our cluster time")
        self.assertEqual(order.resource.name, f"{self.proposal.project.name} - HPC")

    def test_an_openportal_allocation_is_created_with_the_name(self):
        """The OpenPortal processor posts the order's name to create its
        allocation; without one the allocation was refused and Errored."""
        offering = marketplace_factories.OfferingFactory(
            name="Isambard 3",
            type=PLUGIN_NAME,
            scope=structure_factories.ServiceSettingsFactory(),
        )
        requested = self.request(offering)

        order = self.allocate()[requested.uuid]

        post_data = CreateAllocationProcessor(order).get_post_data()
        self.assertEqual(
            post_data["name"], f"{self.proposal.project.name} - Isambard 3"
        )
