import uuid as uuid_module

from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_mastermind.invoices.tests import factories


class ProjectCreditListScopingTest(test.APITransactionTestCase):
    """ProjectCredit.list is overridden so project members can read their own
    project's credits, which the homeport accounting widget needs. The override
    must scope to the projects the user has a role in rather than bypassing
    filtering: it stands in for GenericRoleFilter, so it has to be at least as
    restrictive.
    """

    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        # The viewset excludes projects whose customer has no CustomerCredit.
        factories.CustomerCreditFactory(customer=self.fixture.customer)
        self.credit = factories.ProjectCreditFactory(project=self.project)

        # An unrelated project in a different organisation, also with credit.
        self.other_customer = structure_factories.CustomerFactory()
        self.other_project = structure_factories.ProjectFactory(
            customer=self.other_customer
        )
        factories.CustomerCreditFactory(customer=self.other_customer)
        self.other_credit = factories.ProjectCreditFactory(project=self.other_project)

        self.url = factories.ProjectCreditFactory.get_list_url()

    def _listed_uuids(self, user):
        self.client.force_authenticate(user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        results = (
            response.data["results"] if "results" in response.data else response.data
        )
        # DRF may render the UUID with or without dashes depending on the
        # field's format, so normalise rather than assuming either.
        return {uuid_module.UUID(entry["uuid"]) for entry in results}

    def test_project_member_sees_own_project_credit(self):
        listed = self._listed_uuids(self.fixture.admin)
        self.assertIn(self.credit.uuid, listed)

    def test_project_member_cannot_see_another_projects_credit(self):
        listed = self._listed_uuids(self.fixture.admin)
        self.assertNotIn(self.other_credit.uuid, listed)

    def test_customer_owner_sees_own_project_credit(self):
        listed = self._listed_uuids(self.fixture.owner)
        self.assertIn(self.credit.uuid, listed)
        self.assertNotIn(self.other_credit.uuid, listed)

    def test_unrelated_user_sees_nothing(self):
        unrelated = structure_factories.UserFactory()
        self.assertEqual(self._listed_uuids(unrelated), set())

    def test_staff_sees_all_project_credits(self):
        listed = self._listed_uuids(self.fixture.staff)
        self.assertIn(self.credit.uuid, listed)
        self.assertIn(self.other_credit.uuid, listed)

    def test_filtering_still_applies(self):
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.get(self.url, {"project_uuid": self.project.uuid.hex})
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        results = (
            response.data["results"] if "results" in response.data else response.data
        )
        listed = {uuid_module.UUID(entry["uuid"]) for entry in results}
        self.assertEqual(listed, {self.credit.uuid})

    def test_invalid_filter_is_rejected(self):
        self.client.force_authenticate(self.fixture.staff)
        response = self.client.get(self.url, {"project_uuid": "not-a-uuid"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
