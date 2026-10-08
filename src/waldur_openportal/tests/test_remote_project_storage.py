"""Storage for an award (RemoteProject), across every project it was attached to.

Storage is cached like usage - under the key of whichever project held the
award, for the award's destination - but it is a series of dated snapshots,
not something to add up. Each window keeps the snapshots taken on its own
days; on a day the award moved, the project it moved to claims the day.
"""

import datetime
import json

import openportal
from django.test import TestCase
from django.urls import reverse
from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_openportal import models, utils

from .test_remote_project_usage import (
    DEST,
    X_KEY,
    Y_KEY,
    AwardTestMixin,
    _attach,
    _d,
    _dt,
)


def _snapshot(key, day, gb, month=3):
    return {
        "project": key,
        "generated_at": f"2026-{month:02d}-{day:02d}T12:00:00Z",
        "project_quotas": {"home": {"limit": "100.00 GB", "usage": f"{gb}.00 GB"}},
        "user_quotas": {},
        "users": {},
    }


def _cache(key, days, resource=DEST, month=3):
    """One cached month holding a snapshot per day, accumulated as sync does."""
    report = None
    for day, gb in sorted(days.items()):
        snapshot = openportal.ProjectStorageReport.from_json(
            json.dumps(_snapshot(key, day, gb, month))
        )
        if report is None:
            report = snapshot
        else:
            report += snapshot
    models.CachedProjectStorageReport.objects.create(
        year=2026,
        month=month,
        project_identifier=key,
        resource=resource,
        report=json.loads(report.to_json()),
    )


def _series(report):
    """[(day, "N.00 GB")] for every snapshot in the report, oldest first."""
    return [
        (
            snapshot.generated_at.day,
            str({str(k): v for k, v in snapshot.project_quotas.items()}["home"].usage),
        )
        for snapshot in sorted(report.daily_reports(), key=lambda s: s.generated_at)
    ]


def _gb(n):
    return f"{n}.00 GB"


def _attach_y(case):
    _attach(case.award, case.y, Y_KEY, _dt(2026, 2, 1))


class StorageReportTest(AwardTestMixin, TestCase):
    def report(self, start=_d(1), end=_d(31)):
        return utils.get_remote_project_storage_report(self.award, start, end)

    def test_snapshots_are_read_from_every_key_the_award_has_had(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {2: 10, 9: 20})
        _cache(Y_KEY, {10: 30, 20: 40})
        self.assertEqual(
            _series(self.report()),
            [(2, _gb(10)), (9, _gb(20)), (10, _gb(30)), (20, _gb(40))],
        )

    def test_the_old_project_s_snapshots_after_the_move_are_not_the_award_s(self):
        """X's latest snapshot is after the award left. filter() would keep it."""
        self.moved_on_the_10th()
        _cache(X_KEY, {2: 10, 15: 99})
        _cache(Y_KEY, {12: 30})
        report = self.report()
        self.assertEqual(_series(report), [(2, _gb(10)), (12, _gb(30))])

    def test_the_latest_snapshot_is_the_newest_in_range(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {2: 10, 15: 99})
        _cache(Y_KEY, {12: 30})
        report = self.report()
        self.assertEqual(report.generated_at.day, 12)
        self.assertEqual(
            str({str(k): v for k, v in report.project_quotas.items()}["home"].usage),
            _gb(30),
        )

    def test_on_the_day_it_moved_only_the_new_project_s_snapshot_counts(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {10: 99})
        _cache(Y_KEY, {10: 30})
        self.assertEqual(_series(self.report()), [(10, _gb(30))])

    def test_it_is_reported_under_the_award_s_identifier(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {2: 10})
        _cache(Y_KEY, {12: 30})
        self.assertEqual(str(self.report().project), "u6ac.brics")

    def test_storage_under_another_resource_is_not_this_award_s(self):
        _attach_y(self)
        _cache(Y_KEY, {2: 10})
        _cache(Y_KEY, {3: 99}, resource="other.brics.somewhere")
        self.assertEqual(_series(self.report()), [(2, _gb(10))])

    def test_an_earlier_award_on_the_same_project_is_not_counted(self):
        _attach(self.award, self.y, Y_KEY, _dt(2026, 3, 10))
        _cache(Y_KEY, {5: 99, 12: 30})
        self.assertEqual(_series(self.report()), [(12, _gb(30))])

    def test_the_range_is_respected(self):
        self.moved_on_the_10th()
        _cache(X_KEY, {2: 10, 9: 20})
        _cache(Y_KEY, {12: 30, 20: 40})
        self.assertEqual(
            _series(self.report(_d(5), _d(15))), [(9, _gb(20)), (12, _gb(30))]
        )

    def test_months_are_read_separately(self):
        _attach_y(self)
        _cache(Y_KEY, {28: 10}, month=2)
        _cache(Y_KEY, {2: 20}, month=3)
        self.assertEqual(
            _series(self.report(datetime.date(2026, 2, 1), _d(31))),
            [(28, _gb(10)), (2, _gb(20))],
        )

    def test_nothing_in_range_is_an_empty_report(self):
        _attach_y(self)
        report = self.report()
        self.assertTrue(report.is_empty())
        self.assertEqual(str(report.project), "u6ac.brics")

    def test_a_pending_award_has_nothing_to_report(self):
        self.award.identifier = ""
        self.award.save()
        self.assertIsNone(self.report())


class StorageEndpointTest(AwardTestMixin, test.APITransactionTestCase):
    def setUp(self):
        super().setUp()
        self.moved_on_the_10th()
        _cache(X_KEY, {2: 10, 15: 99})
        _cache(Y_KEY, {12: 30})
        self.client.force_authenticate(structure_factories.UserFactory(is_staff=True))
        self.url = reverse(
            "openportal-remote-project-storage-report",
            kwargs={"uuid": self.award.uuid.hex},
        )

    def test_it_returns_the_combined_report_and_its_windows(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["report"]["project"], "u6ac.brics")
        # The latest snapshot is the top level; daily_reports holds the rest.
        self.assertEqual(response.data["report"]["generated_at"][:10], "2026-03-12")
        self.assertEqual(list(response.data["report"]["daily_reports"]), ["2026-03-02"])
        self.assertEqual(response.json()["latest"][:10], "2026-03-12")
        self.assertEqual(
            [w["project_uuid"] for w in response.data["windows"]],
            [self.x.uuid.hex, self.y.uuid.hex],
        )

    def test_nothing_in_range_has_no_latest(self):
        response = self.client.get(
            self.url, {"start": "2026-03-20", "end": "2026-03-25"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["latest"])

    def test_a_backwards_range_is_rejected(self):
        response = self.client.get(
            self.url, {"start": "2026-03-20", "end": "2026-03-01"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_someone_who_cannot_see_the_project_cannot_see_its_storage(self):
        self.client.force_authenticate(structure_factories.UserFactory())
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
