import datetime

from rest_framework import status, test
from rest_framework.reverse import reverse

from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import models


def _dt(year, month, day):
    return datetime.datetime(year, month, day, tzinfo=datetime.timezone.utc)


def _make_managed_project(**kwargs):
    defaults = {
        "destination": "test-destination",
        "identifier": "test-identifier",
    }
    defaults.update(kwargs)
    return models.ManagedProject.objects.create(**defaults)


def _make_attachment(managed_project, project, attached_at, detached_at=None):
    return models.ManagedProjectAttachment.objects.create(
        managed_project=managed_project,
        project=project,
        attached_at=attached_at,
        detached_at=detached_at,
    )


class ProjectAwardHistoryTest(test.APITestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        self.list_url = reverse("openportal-project-award-history-list")

    def _detail_url(self, project):
        return reverse(
            "openportal-project-award-history-detail",
            kwargs={"uuid": project.uuid.hex},
        )

    def test_list_without_project_uuid_is_rejected(self):
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_retrieve_returns_award_history(self):
        managed_project = _make_managed_project(identifier="award-1")
        _make_attachment(
            managed_project, self.project, _dt(2026, 1, 1), _dt(2026, 2, 1)
        )
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self._detail_url(self.project))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["project_uuid"], str(self.project.uuid))
        self.assertEqual(len(response.data["awards"]), 1)
        award = response.data["awards"][0]
        self.assertEqual(award["managed_project_identifier"], "award-1")
        self.assertFalse(award["is_current"])

    def test_list_with_project_uuid_returns_the_history(self):
        managed_project = _make_managed_project(identifier="award-2")
        _make_attachment(managed_project, self.project, _dt(2026, 1, 1))
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(
            self.list_url, {"project_uuid": self.project.uuid.hex}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(len(response.data[0]["awards"]), 1)
        self.assertTrue(response.data[0]["awards"][0]["is_current"])

    def test_multiple_awards_are_all_listed(self):
        _make_attachment(
            _make_managed_project(identifier="award-a"),
            self.project,
            _dt(2026, 1, 1),
            _dt(2026, 2, 1),
        )
        _make_attachment(
            _make_managed_project(identifier="award-b"), self.project, _dt(2026, 2, 1)
        )
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self._detail_url(self.project))

        self.assertEqual(len(response.data["awards"]), 2)

    def test_project_member_can_view_their_own_project_history(self):
        managed_project = _make_managed_project(identifier="award-3")
        _make_attachment(managed_project, self.project, _dt(2026, 1, 1))
        self.client.force_authenticate(self.fixture.admin)

        response = self.client.get(self._detail_url(self.project))

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_without_access_cannot_view_other_project_history(self):
        other_fixture = structure_fixtures.ProjectFixture()
        self.client.force_authenticate(self.fixture.admin)

        response = self.client.get(self._detail_url(other_fixture.project))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class ManagedProjectHistoryTest(test.APITestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        self.other_fixture = structure_fixtures.ProjectFixture()
        self.other_project = self.other_fixture.project
        self.managed_project = _make_managed_project(identifier="shared-award")
        self.list_url = reverse("openportal-award-project-history-list")

    def _query(self, **extra):
        params = {
            "identifier": self.managed_project.identifier,
            "destination": self.managed_project.destination,
        }
        params.update(extra)
        return params

    def test_list_without_identifier_or_destination_is_rejected(self):
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(
            self.list_url, {"identifier": self.managed_project.identifier}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_staff_sees_every_project_in_the_history(self):
        _make_attachment(
            self.managed_project, self.project, _dt(2026, 1, 1), _dt(2026, 2, 1)
        )
        _make_attachment(self.managed_project, self.other_project, _dt(2026, 2, 1))
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.list_url, self._query())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_regular_user_only_sees_projects_they_have_access_to(self):
        _make_attachment(
            self.managed_project, self.project, _dt(2026, 1, 1), _dt(2026, 2, 1)
        )
        _make_attachment(self.managed_project, self.other_project, _dt(2026, 2, 1))
        self.client.force_authenticate(self.fixture.admin)

        response = self.client.get(self.list_url, self._query())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["project_uuid"], str(self.project.uuid))

    def test_rows_with_deleted_project_are_hidden_from_non_staff(self):
        _make_attachment(
            self.managed_project, self.project, _dt(2026, 1, 1), _dt(2026, 2, 1)
        )
        _make_attachment(self.managed_project, None, _dt(2026, 2, 1))
        self.client.force_authenticate(self.fixture.admin)

        response = self.client.get(self.list_url, self._query())

        self.assertEqual(len(response.data), 1)

    def test_rows_with_deleted_project_are_visible_to_staff(self):
        _make_attachment(self.managed_project, None, _dt(2026, 1, 1))
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.list_url, self._query())

        self.assertEqual(len(response.data), 1)
        self.assertIsNone(response.data[0]["project_uuid"])

    def test_no_access_to_any_project_returns_empty_list(self):
        _make_attachment(self.managed_project, self.other_project, _dt(2026, 1, 1))
        self.client.force_authenticate(self.fixture.admin)

        response = self.client.get(self.list_url, self._query())

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

    def test_different_award_with_same_identifier_but_different_destination_is_not_mixed_in(
        self,
    ):
        other_award = _make_managed_project(
            identifier=self.managed_project.identifier,
            destination="a-different-destination",
        )
        _make_attachment(self.managed_project, self.project, _dt(2026, 1, 1))
        _make_attachment(other_award, self.other_project, _dt(2026, 1, 1))
        self.client.force_authenticate(self.fixture.staff)

        response = self.client.get(self.list_url, self._query())

        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["project_uuid"], str(self.project.uuid))
