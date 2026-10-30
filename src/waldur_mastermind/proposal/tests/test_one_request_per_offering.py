from rest_framework import status, test

from waldur_mastermind.proposal import models
from waldur_mastermind.proposal.tests import factories, fixtures


class OneRequestPerOfferingTest(test.APITestCase):
    def setUp(self):
        self.fixture = fixtures.ProposalFixture()
        self.proposal = self.fixture.proposal
        self.offering = self.fixture.requested_offering_accepted
        self.url = factories.RequestedResourceFactory.get_list_url(self.proposal)

    def add(self):
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.post(
            self.url, {"requested_offering_uuid": self.offering.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        return response.data["uuid"]

    def requests(self):
        return models.RequestedResource.objects.filter(
            proposal=self.proposal, requested_offering=self.offering
        )

    def test_latest_request_replaces_the_earlier_one(self):
        call = self.proposal.round.call
        call.one_request_per_offering = True
        call.save()
        self.add()
        latest = self.add()
        self.assertEqual(
            [r.uuid.hex for r in self.requests()], [latest.replace("-", "")]
        )

    def test_upstream_default_allows_several(self):
        before = self.requests().count()
        self.add()
        self.add()
        self.assertEqual(self.requests().count(), before + 2)
