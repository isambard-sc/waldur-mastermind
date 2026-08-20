import datetime
from contextlib import contextmanager
from unittest import mock

from django.test import TestCase

from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import models, utils


def _dt(year, month, day, hour=0, minute=0):
    return datetime.datetime(
        year, month, day, hour, minute, tzinfo=datetime.timezone.utc
    )


def _make_managed_project(project, project_template=None, **kwargs):
    defaults = {
        "destination": "test-destination",
        "identifier": "test-identifier",
        "local_identifier": "testproj.testportal",
        "project": project,
        "project_template": project_template,
    }
    defaults.update(kwargs)
    return models.ManagedProject.objects.create(**defaults)


def _record_event(managed_project, event_type, when):
    entry = models.ManagedProjectAuditEntry.objects.create(
        identifier=managed_project.identifier,
        destination=managed_project.destination,
        managed_project=managed_project,
        event_type=event_type,
    )
    models.ManagedProjectAuditEntry.objects.filter(pk=entry.pk).update(timestamp=when)
    return entry


def _set_created(managed_project, when):
    models.ManagedProject.objects.filter(pk=managed_project.pk).update(created=when)
    managed_project.refresh_from_db()


class GetManagedProjectWindowsTest(TestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.managed_project = _make_managed_project(self.fixture.project)

    def test_no_events_and_currently_attached_uses_created_as_open_window(self):
        _set_created(self.managed_project, _dt(2026, 1, 5))

        windows = utils._get_managed_project_windows(self.managed_project)

        self.assertEqual(windows, [(datetime.date(2026, 1, 5), None)])

    def test_no_events_and_never_attached_returns_no_windows(self):
        self.managed_project.project = None
        self.managed_project.save(update_fields=["project"])

        windows = utils._get_managed_project_windows(self.managed_project)

        self.assertEqual(windows, [])

    def test_first_event_is_detach_uses_created_as_implicit_start(self):
        _set_created(self.managed_project, _dt(2026, 1, 1))
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_DETACHED,
            _dt(2026, 2, 1),
        )
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 3, 1),
        )

        windows = utils._get_managed_project_windows(self.managed_project)

        self.assertEqual(
            windows,
            [
                (datetime.date(2026, 1, 1), datetime.date(2026, 2, 1)),
                (datetime.date(2026, 3, 1), None),
            ],
        )

    def test_first_event_is_attach_ignores_created(self):
        _set_created(self.managed_project, _dt(2026, 1, 1))
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 2, 1),
        )

        windows = utils._get_managed_project_windows(self.managed_project)

        self.assertEqual(windows, [(datetime.date(2026, 2, 1), None)])

    def test_same_day_detach_and_reattach_merges_into_one_window(self):
        _set_created(self.managed_project, _dt(2026, 1, 1))
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_DETACHED,
            _dt(2026, 2, 10, 9),
        )
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 2, 10, 17),
        )

        windows = utils._get_managed_project_windows(self.managed_project)

        self.assertEqual(windows, [(datetime.date(2026, 1, 1), None)])

    def test_flash_attach_with_no_same_day_reattach_is_its_own_window(self):
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 5, 10, 9),
        )
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_DETACHED,
            _dt(2026, 5, 10, 17),
        )
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 5, 20),
        )

        windows = utils._get_managed_project_windows(self.managed_project)

        self.assertEqual(
            windows,
            [
                (datetime.date(2026, 5, 10), datetime.date(2026, 5, 10)),
                (datetime.date(2026, 5, 20), None),
            ],
        )

    def test_multiple_full_cycles_with_a_genuine_gap(self):
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 1, 1),
        )
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_DETACHED,
            _dt(2026, 1, 10),
        )
        _record_event(
            self.managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 1, 20),
        )

        windows = utils._get_managed_project_windows(self.managed_project)

        self.assertEqual(
            windows,
            [
                (datetime.date(2026, 1, 1), datetime.date(2026, 1, 10)),
                (datetime.date(2026, 1, 20), None),
            ],
        )


class MergeAdjacentWindowsTest(TestCase):
    def test_empty_list(self):
        self.assertEqual(utils._merge_adjacent_windows([]), [])

    def test_touching_windows_merge(self):
        windows = [
            (datetime.date(2026, 1, 1), datetime.date(2026, 1, 10)),
            (datetime.date(2026, 1, 10), datetime.date(2026, 1, 20)),
        ]

        self.assertEqual(
            utils._merge_adjacent_windows(windows),
            [(datetime.date(2026, 1, 1), datetime.date(2026, 1, 20))],
        )

    def test_gap_between_windows_is_not_merged(self):
        windows = [
            (datetime.date(2026, 1, 1), datetime.date(2026, 1, 10)),
            (datetime.date(2026, 1, 15), None),
        ]

        self.assertEqual(utils._merge_adjacent_windows(windows), windows)


@contextmanager
def _patch_report(total_hours_per_day):
    """
    Replace CachedProjectUsageReport.get_report() and openportal.DateRange
    with simple fakes so _sum_usage_over_windows can be tested without a
    real OpenPortal installation. The fake report returns
    total_hours_per_day * (number of days in the requested range).
    """

    class _FakeUsage:
        def __init__(self, hours):
            self.hours = hours

    class _FakeFilteredReport:
        def __init__(self, hours):
            self.total_usage = _FakeUsage(hours)

    class _FakeReport:
        def filter(self, date_range):
            days = (date_range.end_date - date_range.start_date).days + 1
            return _FakeFilteredReport(days * total_hours_per_day)

    class _FakeDateRange:
        def __init__(self, start_date, end_date):
            self.start_date = start_date
            self.end_date = end_date

    with (
        mock.patch.object(
            models.CachedProjectUsageReport, "get_report", return_value=_FakeReport()
        ),
        mock.patch("waldur_openportal.op.DateRange", _FakeDateRange),
    ):
        yield


class SumUsageOverWindowsTest(TestCase):
    project_identifier = "testproj.testportal"
    resource = "test-destination"

    def _make_cached_report(self, year, month):
        return models.CachedProjectUsageReport.objects.create(
            year=year,
            month=month,
            project_identifier=self.project_identifier,
            resource=self.resource,
            is_complete=True,
            report={},
        )

    def test_no_windows_returns_zero(self):
        self.assertEqual(
            utils._sum_usage_over_windows([], self.project_identifier, self.resource),
            0.0,
        )

    def test_missing_identifier_or_resource_returns_zero(self):
        windows = [(datetime.date(2026, 1, 1), None)]

        self.assertEqual(utils._sum_usage_over_windows(windows, "", self.resource), 0.0)
        self.assertEqual(
            utils._sum_usage_over_windows(windows, self.project_identifier, ""), 0.0
        )

    def test_full_month_window_counts_the_whole_report(self):
        self._make_cached_report(2026, 3)
        windows = [(datetime.date(2026, 3, 1), datetime.date(2026, 3, 31))]

        with _patch_report(total_hours_per_day=2.0):
            total = utils._sum_usage_over_windows(
                windows, self.project_identifier, self.resource
            )

        self.assertAlmostEqual(total, 31 * 2.0)

    def test_partial_month_window_is_prorated(self):
        self._make_cached_report(2026, 3)
        windows = [(datetime.date(2026, 3, 20), datetime.date(2026, 3, 31))]

        with _patch_report(total_hours_per_day=2.0):
            total = utils._sum_usage_over_windows(
                windows, self.project_identifier, self.resource
            )

        self.assertAlmostEqual(total, 12 * 2.0)

    def test_window_outside_report_month_contributes_nothing(self):
        self._make_cached_report(2026, 3)
        windows = [(datetime.date(2026, 4, 1), None)]

        with _patch_report(total_hours_per_day=2.0):
            total = utils._sum_usage_over_windows(
                windows, self.project_identifier, self.resource
            )

        self.assertEqual(total, 0.0)

    def test_open_window_sums_every_matching_cached_month(self):
        self._make_cached_report(2026, 3)
        self._make_cached_report(2026, 4)
        windows = [(datetime.date(2026, 3, 15), None)]

        with _patch_report(total_hours_per_day=1.0):
            total = utils._sum_usage_over_windows(
                windows, self.project_identifier, self.resource
            )

        self.assertAlmostEqual(total, 17 * 1.0 + 30 * 1.0)

    def test_report_for_a_different_resource_is_ignored(self):
        models.CachedProjectUsageReport.objects.create(
            year=2026,
            month=3,
            project_identifier=self.project_identifier,
            resource="some-other-destination",
            is_complete=True,
            report={},
        )
        windows = [(datetime.date(2026, 3, 1), datetime.date(2026, 3, 31))]

        with _patch_report(total_hours_per_day=2.0):
            total = utils._sum_usage_over_windows(
                windows, self.project_identifier, self.resource
            )

        self.assertEqual(total, 0.0)


class GetAwardUsageInfoTest(TestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project

    def test_raises_for_non_project_argument(self):
        with self.assertRaises(TypeError):
            utils.get_award_usage_info("not-a-project")

    def test_no_managed_project_returns_none_and_zero(self):
        result = utils.get_award_usage_info(self.project)

        self.assertEqual(result, (None, 0.0))

    def test_no_project_template_returns_none_allocation(self):
        _make_managed_project(self.project, project_template=None)

        with mock.patch.object(utils, "_sum_usage_over_windows", return_value=42.0):
            result = utils.get_award_usage_info(self.project)

        self.assertEqual(result, (None, 42.0))

    def test_no_allocation_in_details_returns_none_allocation(self):
        template = models.ProjectTemplate.objects.create(
            name="tmpl", portal="test-portal"
        )
        _make_managed_project(self.project, project_template=template)

        fake_details = mock.Mock(allocation=None)
        with (
            mock.patch.object(
                models.ManagedProject, "get_details", return_value=fake_details
            ),
            mock.patch.object(utils, "_sum_usage_over_windows", return_value=10.0),
        ):
            result = utils.get_award_usage_info(self.project)

        self.assertEqual(result, (None, 10.0))

    def test_converts_allocation_to_credits_using_project_template(self):
        template = models.ProjectTemplate.objects.create(
            name="tmpl",
            portal="test-portal",
            allocation_units_mapping={"NHR": 1.0},
        )
        managed_project = _make_managed_project(self.project, project_template=template)

        fake_allocation = mock.Mock(units="NHR", size=1000.0)
        fake_details = mock.Mock(allocation=fake_allocation)
        with (
            mock.patch.object(
                models.ManagedProject, "get_details", return_value=fake_details
            ),
            mock.patch.object(
                utils, "_sum_usage_over_windows", return_value=250.0
            ) as mock_sum,
        ):
            result = utils.get_award_usage_info(self.project)

        self.assertEqual(result, (1000.0, 250.0))
        mock_sum.assert_called_once()
        _, kwargs = mock_sum.call_args
        self.assertEqual(kwargs["project_identifier"], managed_project.local_identifier)
        self.assertEqual(kwargs["resource"], managed_project.destination)
