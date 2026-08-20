from unittest import mock

from rest_framework import status, test
from rest_framework.reverse import reverse

from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import models, utils


def _make_managed_project(project, **kwargs):
    defaults = {
        "destination": "test-destination",
        "identifier": "test-identifier",
        "local_identifier": "testproj.testportal",
        "project": project,
    }
    defaults.update(kwargs)
    return models.ManagedProject.objects.create(**defaults)


class ManagedProjectAccountingSummaryTest(test.APITestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        self.list_url = reverse("openportal-managed-project-accounting-summary-list")

    def _detail_url(self, project):
        return reverse(
            "openportal-managed-project-accounting-summary-detail",
            kwargs={"uuid": project.uuid.hex},
        )

    def test_list_without_project_uuid_is_rejected(self):
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_with_project_uuid_returns_the_summary(self):
        self.client.force_authenticate(self.fixture.staff)

        with mock.patch.object(
            utils, "get_award_usage_info", return_value=(1000.0, 250.0)
        ):
            response = self.client.get(
                self.list_url, {"project_uuid": self.project.uuid.hex}
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["project_uuid"], str(self.project.uuid))
        self.assertEqual(response.data[0]["allocation_credits"], 1000.0)
        self.assertEqual(response.data[0]["usage_credits"], 250.0)
        self.assertEqual(response.data[0]["remaining_credits"], 750.0)

    def test_retrieve_by_project_uuid(self):
        self.client.force_authenticate(self.fixture.staff)

        with mock.patch.object(
            utils, "get_award_usage_info", return_value=(1000.0, 250.0)
        ):
            response = self.client.get(self._detail_url(self.project))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["allocation_credits"], 1000.0)
        self.assertEqual(response.data["usage_credits"], 250.0)
        self.assertEqual(response.data["remaining_credits"], 750.0)

    def test_has_award_is_false_when_no_managed_project_attached(self):
        self.client.force_authenticate(self.fixture.staff)

        with mock.patch.object(
            utils, "get_award_usage_info", return_value=(None, 0.0)
        ):
            response = self.client.get(self._detail_url(self.project))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["has_award"])
        self.assertIsNone(response.data["allocation_credits"])
        self.assertIsNone(response.data["remaining_credits"])
        self.assertEqual(response.data["usage_credits"], 0.0)

    def test_has_award_is_true_when_a_managed_project_is_attached(self):
        _make_managed_project(self.project)
        self.client.force_authenticate(self.fixture.staff)

        with mock.patch.object(
            utils, "get_award_usage_info", return_value=(1000.0, 250.0)
        ):
            response = self.client.get(self._detail_url(self.project))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["has_award"])

    def test_regular_user_without_access_cannot_retrieve_other_projects(self):
        other_fixture = structure_fixtures.ProjectFixture()
        self.client.force_authenticate(self.fixture.admin)

        response = self.client.get(self._detail_url(other_fixture.project))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_project_member_can_retrieve_their_own_project(self):
        self.client.force_authenticate(self.fixture.admin)

        with mock.patch.object(
            utils, "get_award_usage_info", return_value=(None, 0.0)
        ):
            response = self.client.get(self._detail_url(self.project))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
