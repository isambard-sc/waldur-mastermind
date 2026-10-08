"""Usage for an award (RemoteProject), across every project it was attached to.

An award's usage is cached under the local identifier of whichever project held
it - "{shortname}.{portal}" - so moving an award from X to Y splits its history
across two keys. Each attachment records its key; each window's usage is read
from that key and filtered to the window's days. On a day the award moves, the
last-attached project claims the whole day, as on the ManagedProject side.
"""

import datetime
import json
from unittest import mock

import openportal
from django.test import TestCase
from django.urls import reverse
from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import config as openportal_config
from waldur_openportal import models, remote_project_service, utils

DEST = "airr.brics.isambard-ai"
X_KEY, Y_KEY = "xshort.awards", "yshort.awards"


def _dt(year, month, day, hour=12):
    return datetime.datetime(year, month, day, hour, tzinfo=datetime.UTC)


def _d(day, month=3):
    return datetime.date(2026, month, day)


def _report(key, days, user=None):
    report = openportal.ProjectUsageReport(openportal.ProjectIdentifier(key))
    for day, hours in days.items():
        daily = openportal.DailyProjectUsageReport()
        if user:
            daily.add_usage(user, openportal.Usage.from_hours(hours))
        else:
            daily.add_unattributed_usage(openportal.Usage.from_hours(hours))
        report.add_report(day, daily)
    return json.loads(report.to_json())


def _cache(key, days, resource=DEST, user=None):
    """One cached month per distinct month in ``days``."""
    by_month = {}
    for day, hours in days.items():
        by_month.setdefault((day.year, day.month), {})[day] = hours
    for (year, month), month_days in by_month.items():
        models.CachedProjectUsageReport.objects.create(
            year=year,
            month=month,
            project_identifier=key,
            resource=resource,
            report=_report(key, month_days, user),
        )


def _attach(remote_project, project, key, attached, detached=None):
    return models.RemoteProjectAttachment.objects.create(
        remote_project=remote_project,
        project=project,
        project_identifier=key,
        attached_at=attached,
        detached_at=detached,
    )


class AwardTestMixin:
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.x = self.fixture.project
        self.y = structure_factories.ProjectFactory(customer=self.fixture.customer)
        self.award = models.RemoteProject.objects.create(
            destination=DEST, identifier="u6ac.brics", current_project=self.y
        )

    def moved_on_the_10th(self):
        """Attached to X on the 1st, moved to Y on the 10th."""
        _attach(self.award, self.x, X_KEY, _dt(2026, 3, 1), _dt(2026, 3, 10, 9))
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 10, 15))

    def hours(self, start=_d(1), end=_d(31)):
        return float(
            utils.get_remote_project_usage_report(
                self.award, start, end
            ).total_usage.hours
        )


class WindowTest(AwardTestMixin, TestCase):
    def windows(self):
        return [
            (w.start, w.end, w.key)
            for w in utils.get_remote_project_windows(self.award)
        ]

    def test_a_single_attachment_is_one_open_window(self):
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 1))
        self.assertEqual(self.windows(), [(_d(1), None, Y_KEY)])

    def test_the_project_moved_to_claims_the_whole_day(self):
        self.moved_on_the_10th()
        self.assertEqual(self.windows(), [(_d(1), _d(9), X_KEY), (_d(10), None, Y_KEY)])

    def test_a_gap_between_attachments_is_nobody_s(self):
        _attach(self.award, self.x, X_KEY, _dt(2026, 3, 1), _dt(2026, 3, 5))
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 8))
        self.assertEqual(self.windows(), [(_d(1), _d(5), X_KEY), (_d(8), None, Y_KEY)])

    def test_an_attachment_wholly_claimed_the_same_day_contributes_nothing(self):
        _attach(self.award, self.x, X_KEY, _dt(2026, 3, 3, 9), _dt(2026, 3, 3, 10))
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 3, 11))
        self.assertEqual(self.windows(), [(_d(3), None, Y_KEY)])

    def test_windows_never_overlap(self):
        for day in (1, 4, 4, 9, 20):
            models.RemoteProjectAttachment.objects.filter(
                remote_project=self.award, detached_at__isnull=True
            ).update(detached_at=_dt(2026, 3, day, 8))
            _attach(self.award, self.y, Y_KEY, _dt(2026, 3, day, 9))
        windows = utils.get_remote_project_windows(self.award)
        for earlier, later in zip(windows, windows[1:]):
            self.assertLess(earlier.end, later.start)

    def test_an_unrecorded_key_is_recomputed_from_the_project(self):
        _attach(self.award, self.x, None, _dt(2026, 3, 1))
        with mock.patch.object(
            utils, "get_local_project_identifier", return_value=X_KEY
        ):
            self.assertEqual(self.windows(), [(_d(1), None, X_KEY)])


class UsageReportTest(AwardTestMixin, TestCase):
    def test_usage_is_read_from_every_key_the_award_has_had(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {_d(2): 1, _d(5): 2})
        _cache(Y_KEY, {_d(12): 4, _d(20): 8})
        self.assertEqual(self.hours(), 15)

    def test_combining_keys_loses_nothing(self):
        """Without a common identifier, combine() silently keeps only the first
        report's usage. This is the test that notices."""
        self.moved_on_the_10th()
        _cache(X_KEY, {_d(2): 1})
        _cache(Y_KEY, {_d(12): 100})
        self.assertEqual(self.hours(), 101)

    def test_on_the_day_it_moved_only_the_new_project_s_usage_counts(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {_d(9): 1, _d(10): 50})
        _cache(Y_KEY, {_d(10): 4})
        self.assertEqual(self.hours(), 5)

    def test_usage_under_another_resource_is_not_this_award_s(self):
        """ManagedProjects once reported zero usage everywhere by confusing
        two different "destinations"; here they must match exactly."""
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 1))
        _cache(Y_KEY, {_d(2): 1})
        _cache(Y_KEY, {_d(3): 64}, resource="some.other.cluster")
        self.assertEqual(self.hours(), 1)

    def test_an_earlier_award_on_the_same_project_is_not_counted(self):
        """Y held a different award on this destination before this one; its
        usage sits under Y's key too, and must not be claimed."""
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 1))
        _cache(Y_KEY, {_d(20, month=2): 999, _d(2): 1})
        self.assertEqual(self.hours(start=_d(1, month=1)), 1)

    def test_the_range_is_respected(self):
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 1))
        _cache(Y_KEY, {_d(2): 1, _d(15): 2, _d(28): 4})
        self.assertEqual(self.hours(start=_d(10), end=_d(20)), 2)

    def test_per_user_usage_survives_combining(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {_d(2): 1}, user=f"alice.{X_KEY}")
        _cache(Y_KEY, {_d(12): 2}, user=f"alice.{Y_KEY}")
        report = utils.get_remote_project_usage_report(self.award, _d(1), _d(31))
        per_day = json.loads(report.to_json())["reports"]
        self.assertEqual(sorted(per_day), ["2026-03-02", "2026-03-12"])
        for day in per_day.values():
            self.assertTrue(day["reports"], "per-user usage was dropped")

    def test_a_pending_award_has_nothing_to_report(self):
        pending = models.RemoteProject.objects.create(
            destination="elsewhere", current_project=self.y
        )
        self.assertIsNone(utils.get_remote_project_usage_report(pending, _d(1), _d(31)))


class EndpointTest(AwardTestMixin, test.APITransactionTestCase):
    def setUp(self):
        super().setUp()
        self.moved_on_the_10th()
        _cache(X_KEY, {_d(2): 1})
        _cache(Y_KEY, {_d(12): 4})
        self.client.force_authenticate(structure_factories.UserFactory(is_staff=True))

    def url(self, name):
        return reverse(
            f"openportal-remote-project-{name}", kwargs={"uuid": self.award.uuid.hex}
        )

    def test_usage_report_returns_the_combined_report_and_its_windows(self):
        response = self.client.get(self.url("usage-report"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_hours"], 5)
        self.assertEqual(
            [w["project_uuid"] for w in response.data["windows"]],
            [self.x.uuid.hex, self.y.uuid.hex],
        )

    def test_total_usage_now_includes_earlier_projects(self):
        """It used to read only the current project's key: 4, not 5."""
        response = self.client.get(self.url("total-usage"))
        self.assertEqual(response.data["total_hours"], 5)

    def test_the_two_endpoints_agree(self):
        self.assertEqual(
            self.client.get(self.url("total-usage")).data["total_hours"],
            self.client.get(self.url("usage-report")).data["total_hours"],
        )

    def test_a_backwards_range_is_rejected(self):
        response = self.client.get(
            self.url("usage-report"), {"start": "2026-03-20", "end": "2026-03-01"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_someone_who_cannot_see_the_project_cannot_see_its_usage(self):
        self.client.force_authenticate(structure_factories.UserFactory())
        response = self.client.get(self.url("usage-report"))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class RecordKeyTest(AwardTestMixin, TestCase):
    def allocation(self, backend_id=Y_KEY):
        return models.RemoteAllocation.objects.create(
            name="award",
            project=self.y,
            service_settings=structure_factories.ServiceSettingsFactory(
                customer=self.fixture.customer
            ),
            backend_id=backend_id,
        )

    def test_opening_an_attachment_records_its_key(self):
        self.award.remote_allocation = self.allocation()
        self.award.save()
        attachment = remote_project_service.ensure_current_attachment(self.award)
        self.assertEqual(attachment.project_identifier, Y_KEY)

    def test_a_missing_key_is_filled_in(self):
        _attach(self.award, self.y, None, _dt(2026, 3, 1))
        self.award.remote_allocation = self.allocation()
        self.award.save()
        remote_project_service.ensure_current_attachment(self.award)
        self.assertEqual(
            self.award.attachments.get(detached_at__isnull=True).project_identifier,
            Y_KEY,
        )

    def test_a_recorded_key_is_never_overwritten(self):
        _attach(self.award, self.y, "recorded.awards", _dt(2026, 3, 1))
        self.award.remote_allocation = self.allocation("different.awards")
        self.award.save()
        remote_project_service.ensure_current_attachment(self.award)
        self.assertEqual(
            self.award.attachments.get(detached_at__isnull=True).project_identifier,
            "recorded.awards",
        )


def openportal_configured():
    """Stub only the boundary: whether OpenPortal is configured, and this
    portal's name ("awards"). Everything between - get_local_project_identifier
    and the shortname lookup - runs for real.

    The first version of these tests replaced get_local_project_identifier
    whole, and so never noticed that the real one could not run: in utils.py,
    `config` was constance's config rather than waldur_openportal.config, so
    config.ensure_config_loaded() raised AttributeError on every call.
    """
    return (
        mock.patch("waldur_openportal.config.ensure_config_loaded"),
        mock.patch("openportal.get_portal", return_value="awards"),
    )


class LocalIdentifierTest(AwardTestMixin, TestCase):
    """The real get_local_project_identifier, not a stand-in for it."""

    def test_it_is_the_project_shortname_at_this_portal(self):
        models.ProjectInfo.objects.create(project=self.x, shortname="xshort")
        loaded, portal = openportal_configured()
        with loaded as ensure_config_loaded, portal:
            ensure_config_loaded.return_value = True
            self.assertEqual(str(utils.get_local_project_identifier(self.x)), X_KEY)

    def test_the_openportal_config_is_the_one_consulted(self):
        """Not constance's, which raised AttributeError on every call."""
        self.assertIs(utils.config, openportal_config)

    def test_an_unconfigured_portal_is_reported_not_crashed_on(self):
        models.ProjectInfo.objects.create(project=self.x, shortname="xshort")
        loaded, _portal = openportal_configured()
        with loaded as ensure_config_loaded:
            ensure_config_loaded.return_value = False
            with self.assertRaises(RuntimeError):
                utils.get_local_project_identifier(self.x)

    def test_refresh_remote_project_gets_past_the_config_check(self):
        """It shared the bug: every award in the periodic refresh sweep
        failed here, and the sweep gave up after 25 of them."""
        loaded, _portal = openportal_configured()
        with loaded as ensure_config_loaded:
            ensure_config_loaded.return_value = False
            self.assertIsNone(utils.refresh_remote_project(self.award))


class BackfillTest(RecordKeyTest):
    def setUp(self):
        super().setUp()
        models.ProjectInfo.objects.create(project=self.x, shortname="xshort")
        models.ProjectInfo.objects.create(project=self.y, shortname="yshort")

    def backfill(self, **kwargs):
        loaded, portal = openportal_configured()
        with loaded as ensure_config_loaded, portal:
            ensure_config_loaded.return_value = True
            return utils.backfill_remote_project_attachments(**kwargs)

    def test_an_award_with_no_attachment_gets_one(self):
        summary = self.backfill()
        self.assertEqual(summary["attachments created"], 1)
        self.assertEqual(self.award.attachments.get().project, self.y)

    def test_keys_are_filled_from_the_allocation_and_from_projects(self):
        self.award.remote_allocation = self.allocation()
        self.award.save()
        _attach(self.award, self.x, None, _dt(2026, 3, 1), _dt(2026, 3, 10))
        _attach(self.award, self.y, None, _dt(2026, 3, 10, 15))
        summary = self.backfill()
        self.assertEqual(summary["keys filled from allocation"], 1)
        self.assertEqual(summary["keys filled from project"], 1)
        keys = list(
            self.award.attachments.order_by("attached_at").values_list(
                "project_identifier", flat=True
            )
        )
        self.assertEqual(keys, [X_KEY, Y_KEY])

    def test_a_first_attachment_stamped_at_tracking_start_is_backdated(self):
        allocation = self.allocation()
        models.RemoteAllocation.objects.filter(pk=allocation.pk).update(
            created=_dt(2025, 11, 1)
        )
        allocation.refresh_from_db()
        self.award.remote_allocation = allocation
        self.award.save()
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 1))
        self.assertEqual(self.backfill()["first attachments backdated"], 1)
        self.assertEqual(
            self.award.attachments.get().attached_at.date(), datetime.date(2025, 11, 1)
        )

    def test_a_record_made_at_the_time_is_left_alone(self):
        """Seconds after its allocation, and windows are whole days."""
        self.award.remote_allocation = self.allocation()
        self.award.save()
        remote_project_service.ensure_current_attachment(self.award)
        self.assertEqual(self.backfill()["first attachments backdated"], 0)

    def test_an_award_that_moved_before_tracking_is_flagged(self):
        self.award.remote_allocation = self.allocation()
        self.award.save()
        _attach(self.award, self.x, X_KEY, _dt(2026, 3, 1), _dt(2026, 3, 10))
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 10, 15))
        self.assertEqual(
            self.backfill()[
                "first attachments with only the award's creation as evidence"
            ],
            1,
        )

    def test_a_dry_run_changes_nothing(self):
        self.award.remote_allocation = self.allocation()
        self.award.save()
        _attach(self.award, self.y, None, _dt(2026, 3, 1))
        self.backfill(dry_run=True)
        self.assertIsNone(self.award.attachments.get().project_identifier)

    def test_a_second_run_finds_nothing_to_do(self):
        self.award.remote_allocation = self.allocation()
        self.award.save()
        _attach(self.award, self.y, None, _dt(2026, 3, 1))
        self.backfill()
        again = self.backfill()
        self.assertEqual(again["attachments created"], 0)
        self.assertEqual(again["keys filled from allocation"], 0)
        self.assertEqual(again["first attachments backdated"], 0)

    def test_a_key_that_disagrees_with_its_project_is_reported(self):
        self.award.remote_allocation = self.allocation()
        self.award.save()
        _attach(self.award, self.y, "drifted.awards", _dt(2026, 3, 1))
        self.assertEqual(self.backfill()["open keys disagreeing with project"], 1)
