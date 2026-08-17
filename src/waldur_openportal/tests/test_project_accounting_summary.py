from rest_framework import status, test
from rest_framework.reverse import reverse

from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_mastermind.marketplace.enums import ResourceStates
from waldur_mastermind.marketplace.tests import factories as marketplace_factories


class ProjectAccountingSummaryTest(test.APITestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        self.url = reverse("openportal-accounting-summary-list")

    def test_offering_name_filter_matches(self):
        offering = marketplace_factories.OfferingFactory(name="HPC Compute")
        marketplace_factories.ResourceFactory(
            project=self.project, offering=offering, state=ResourceStates.OK
        )
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.url, {"offering_name": "hpc"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(
            str(self.project.uuid), {item["project_uuid"] for item in response.data}
        )

    def test_offering_name_filter_excludes_non_matching_projects(self):
        other_project = self.fixture.project
        offering = marketplace_factories.OfferingFactory(name="HPC Compute")
        marketplace_factories.ResourceFactory(
            project=self.project, offering=offering, state=ResourceStates.OK
        )
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.url, {"offering_name": "hpc"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        project_uuids = {item["project_uuid"] for item in response.data}
        self.assertIn(str(self.project.uuid), project_uuids)
        self.assertNotIn(str(other_project.uuid), project_uuids)

    def test_offering_name_filter_ignores_non_ok_resources(self):
        offering = marketplace_factories.OfferingFactory(name="HPC Compute")
        marketplace_factories.ResourceFactory(
            project=self.project,
            offering=offering,
            state=ResourceStates.TERMINATED,
        )
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.url, {"offering_name": "hpc"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        project_uuids = {item["project_uuid"] for item in response.data}
        self.assertNotIn(str(self.project.uuid), project_uuids)

    def test_offering_names_omitted_by_default(self):
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.url, {"project_uuid": self.project.uuid.hex})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn("offering_names", response.data[0])

    def test_include_offering_names(self):
        offering = marketplace_factories.OfferingFactory(name="HPC Compute")
        marketplace_factories.ResourceFactory(
            project=self.project, offering=offering, state=ResourceStates.OK
        )
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(
            self.url,
            {"project_uuid": self.project.uuid.hex, "include_offering_names": "true"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["offering_names"], ["HPC Compute"])

    def test_include_offering_names_on_retrieve(self):
        offering = marketplace_factories.OfferingFactory(name="HPC Compute")
        marketplace_factories.ResourceFactory(
            project=self.project, offering=offering, state=ResourceStates.OK
        )
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(
            reverse(
                "openportal-accounting-summary-detail",
                kwargs={"uuid": self.project.uuid.hex},
            ),
            {"include_offering_names": "true"},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["offering_names"], ["HPC Compute"])
