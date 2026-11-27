"""Spend-profile forfeits, added to the usage report as it arrives.

The award: 1000 NHR over 2027, used at 1 NHR a day from 1 April. Its
profile asks for at least 200 NHR from April to June, and 50 NHR more from
July to September. So when June ends, 91 NHR has been used and 109 NHR is
forfeit; when September ends the minimums so far (250 NHR) are covered by
what was used (183 NHR) and that forfeit, so nothing more is.
"""

import datetime
import json
import unittest
from unittest import mock

import openportal
from django.core.exceptions import ValidationError
from django.test import TestCase

from waldur_core.structure.tests import factories as structure_factories
from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import backend as openportal_backend
from waldur_openportal import models, spend_profiles, utils

needs_spend_profiles = unittest.skipUnless(
    spend_profiles.is_supported(), "needs openportal 0.94 (spend profiles)"
)

PORTAL = "testportal"
IDENTIFIER = f"sp01.{PORTAL}"
RESOURCE = "brics.aip2.clusters.shared"
USAGE_FROM = datetime.date(2027, 4, 1)
PROFILE = [
    {"from": "2027-04-01", "minimum": "200 NHR"},
    {"from": "2027-07-01", "minimum": "50 NHR"},
    {"from": "2027-10-01"},
]
AWARD = {
    "name": "Award",
    "start_date": "2027-01-01",
    "end_date": "2027-12-31",
    "allocation": "1000 NHR",
    "spend_profile": PROFILE,
}


def _month(year, month):
    start = datetime.date(year, month, 1)
    end = (start.replace(day=28) + datetime.timedelta(days=4)).replace(
        day=1
    ) - datetime.timedelta(days=1)
    return openportal.DateRange(start, end)


def _cluster_report(month, complete=True, unit="NHR"):
    """The month's report as the cluster sends it: alice, 1 NHR a day from
    USAGE_FROM. unit=None gives one from an agent before usage units."""
    report = openportal.ProjectUsageReport(
        openportal.ProjectIdentifier(IDENTIFIER), unit=openportal.UsageUnit("NHR")
    )
    day = month.start_date
    while day <= month.end_date:
        daily = openportal.DailyProjectUsageReport()
        if day >= USAGE_FROM:
            daily.add_usage("alice", openportal.Usage.from_hours(1))
        if complete:
            daily.set_complete()
        report.add_report(day, daily)
        day += datetime.timedelta(days=1)
    if unit is None:
        data = json.loads(report.to_json())
        data.pop("usage_unit", None)
        report = openportal.ProjectUsageReport.from_json(json.dumps(data))
    return report


def _on(day):
    return mock.patch.object(
        spend_profiles.timezone,
        "now",
        return_value=datetime.datetime(
            day.year, day.month, day.day, 0, 5, tzinfo=datetime.UTC
        ),
    )


@needs_spend_profiles
class ForfeitTest(TestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        models.ProjectInfo.objects.create(project=self.project, shortname="sp01")
        self.managed_project = models.ManagedProject.objects.create(
            destination="airr.brics.isambard-ai",
            identifier="award.airr",
            local_identifier=IDENTIFIER,
            project=self.project,
            details=AWARD,
        )
        models.ManagedProjectAttachment.objects.create(
            managed_project=self.managed_project,
            project=self.project,
            attached_at=datetime.datetime(2027, 1, 1, 9, tzinfo=datetime.UTC),
        )
        self.allocation = self.make_allocation()
        for patcher in (
            mock.patch(
                "waldur_openportal.config.ensure_config_loaded", return_value=True
            ),
            mock.patch("openportal.get_portal", return_value=PORTAL),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def make_allocation(self):
        return models.Allocation.objects.create(
            name="cluster",
            project=self.project,
            service_settings=structure_factories.ServiceSettingsFactory(
                customer=self.fixture.customer
            ),
            backend_id=IDENTIFIER,
        )

    def cache(self, month, report):
        models.CachedProjectUsageReport.objects.update_or_create(
            year=month.start_date.year,
            month=month.start_date.month,
            project_identifier=IDENTIFIER,
            resource=RESOURCE,
            defaults={"is_complete": True, "report": json.loads(report.to_json())},
        )

    def sync(self, month, today, report=None, allocation=None):
        """One sync of the month's report, cached as sync_usage caches it."""
        report = report or _cluster_report(month)
        with _on(today):
            report = spend_profiles.add_forfeits(
                allocation or self.allocation, report, month, RESOURCE
            )
        self.cache(month, report)
        return report

    def sync_april_to(self, last_month):
        for month in range(4, last_month):
            self.cache(_month(2027, month), _cluster_report(_month(2027, month)))

    def test_a_shortfall_is_charged_the_day_after_the_period_ends(self):
        self.sync_april_to(6)
        june = _month(2027, 6)

        report = self.sync(june, datetime.date(2027, 7, 1))

        forfeit = models.AwardForfeit.objects.get()
        self.assertEqual(forfeit.date, datetime.date(2027, 6, 30))
        self.assertEqual(float(forfeit.amount), 109.0)
        self.assertEqual(forfeit.units, "NHR")
        self.assertEqual(forfeit.working["cumulative_minimum"], 200.0)
        self.assertEqual(forfeit.working["cumulative_charges"], 91.0)

        last_day = report.get_report(datetime.date(2027, 6, 30))
        self.assertAlmostEqual(last_day.total_usage.hours, 1 + 109)
        self.assertEqual(last_day.components, [spend_profiles.FORFEIT_COMPONENT])
        self.assertEqual(last_day.num_jobs, 0)
        self.assertTrue(last_day.is_complete)
        self.assertTrue(report.is_complete)
        self.assertAlmostEqual(report.total_usage.hours, 30 + 109)
        self.assertIn(openportal.UserIdentifier(f"forfeit.{IDENTIFIER}"), report.users)
        self.assertEqual(report.unmapped_users, ["alice"])
        self.assertTrue(
            models.ManagedProjectAuditEntry.objects.filter(
                managed_project=self.managed_project,
                event_type=models.ManagedProjectAuditEventType.FORFEIT_CHARGED,
            ).exists()
        )

    def test_a_forfeit_does_not_settle_a_day_the_cluster_has_not(self):
        self.sync_april_to(6)
        june = _month(2027, 6)

        report = self.sync(
            june, datetime.date(2027, 7, 1), report=_cluster_report(june, False)
        )

        self.assertEqual(models.AwardForfeit.objects.count(), 1)
        self.assertFalse(report.get_report(datetime.date(2027, 6, 30)).is_complete)
        self.assertFalse(report.is_complete)

    def test_a_report_from_before_units_is_taken_as_node_hours(self):
        self.sync_april_to(6)
        june = _month(2027, 6)

        report = self.sync(
            june, datetime.date(2027, 7, 1), report=_cluster_report(june, unit=None)
        )

        self.assertEqual(report.unit.name, "NHR")
        self.assertAlmostEqual(report.total_usage.hours, 30 + 109)

    def test_every_later_report_of_the_month_carries_the_same_forfeit(self):
        self.sync_april_to(6)
        june = _month(2027, 6)
        self.sync(june, datetime.date(2027, 7, 1))

        # Late usage changes the report; the forfeit stays as charged.
        report = self.sync(june, datetime.date(2027, 7, 2))

        self.assertEqual(models.AwardForfeit.objects.count(), 1)
        self.assertAlmostEqual(report.total_usage.hours, 30 + 109)

    def test_nothing_is_charged_before_the_period_ends(self):
        self.sync_april_to(6)
        report = self.sync(_month(2027, 6), datetime.date(2027, 6, 30))

        self.assertFalse(models.AwardForfeit.objects.exists())
        self.assertAlmostEqual(report.total_usage.hours, 30)

    def test_an_earlier_forfeit_counts_towards_later_minimums(self):
        self.sync_april_to(6)
        self.sync(_month(2027, 6), datetime.date(2027, 7, 1))
        self.cache(_month(2027, 7), _cluster_report(_month(2027, 7)))
        self.cache(_month(2027, 8), _cluster_report(_month(2027, 8)))

        self.sync(_month(2027, 9), datetime.date(2027, 10, 1))

        september = models.AwardForfeit.objects.get(
            period_from=datetime.date(2027, 7, 1)
        )
        self.assertEqual(float(september.amount), 0.0)
        self.assertEqual(september.working["cumulative_minimum"], 250.0)
        self.assertEqual(september.working["cumulative_charges"], 183.0 + 109.0)

    def test_the_progress_shows_the_forfeit(self):
        self.sync_april_to(6)
        self.sync(_month(2027, 6), datetime.date(2027, 7, 1))

        with _on(datetime.date(2027, 7, 1)):
            result = spend_profiles.progress(
                self.managed_project, datetime.date(2027, 7, 1)
            )
        april = result["periods"][0]
        self.assertEqual(april["forfeit"], 109.0)
        self.assertAlmostEqual(april["cumulative_spend"], 91 + 109)
        self.assertIsNone(result["periods"][1]["forfeit"])

    def test_only_one_allocation_of_a_project_is_charged(self):
        self.sync_april_to(6)
        second = self.make_allocation()

        report = self.sync(
            _month(2027, 6), datetime.date(2027, 7, 1), allocation=second
        )

        self.assertFalse(models.AwardForfeit.objects.exists())
        self.assertAlmostEqual(report.total_usage.hours, 30)

    def test_the_month_is_held_open_if_the_forfeit_cannot_be_charged(self):
        self.sync_april_to(6)
        with mock.patch.object(
            spend_profiles, "_charge_forfeit", side_effect=RuntimeError("boom")
        ):
            report = self.sync(_month(2027, 6), datetime.date(2027, 7, 1))

        self.assertFalse(models.AwardForfeit.objects.exists())
        self.assertFalse(report.is_complete)

    def test_nothing_is_charged_unless_minimums_are_claimed(self):
        self.sync_april_to(6)
        with mock.patch.object(
            spend_profiles,
            "SUPPORTED_FEATURES",
            frozenset({spend_profiles.AWARD_SPEND_MAXIMUMS}),
        ):
            report = self.sync(_month(2027, 6), datetime.date(2027, 7, 1))

        self.assertFalse(models.AwardForfeit.objects.exists())
        self.assertAlmostEqual(report.total_usage.hours, 30)


class ForfeitIsReservedTest(TestCase):
    def test_no_person_may_be_called_forfeit(self):
        user_info = models.UserInfo.objects.create(
            user=structure_factories.UserFactory()
        )
        with self.assertRaises(ValidationError):
            user_info.set_shortname("forfeit")


class ForfeitUserIsNeverAPersonTest(TestCase):
    def test_a_forfeit_identifier_resolves_to_no_one(self):
        identifier = f"forfeit.{IDENTIFIER}"
        with mock.patch(
            "waldur_openportal.utils._resolve_useridentifier_from_slugs"
        ) as from_slugs:
            result = utils.resolve_useridentifiers([identifier])
        self.assertEqual(result, {identifier: None})
        from_slugs.assert_not_called()


class SiteSyncTest(TestCase):
    """The site's sync adds forfeits to each report and bills a completed
    month's late usage, as the awarding side does."""

    def test_sync_adds_forfeits_and_reconciles(self):
        fixture = structure_fixtures.ProjectFixture()
        allocation = models.Allocation.objects.create(
            name="cluster",
            project=fixture.project,
            service_settings=structure_factories.ServiceSettingsFactory(
                customer=fixture.customer
            ),
            backend_id=IDENTIFIER,
        )
        backend = openportal_backend.OpenPortalBackend.__new__(
            openportal_backend.OpenPortalBackend
        )
        backend._client = mock.Mock()
        backend._client.destination.return_value = RESOURCE
        backend._client.get_usage_report.side_effect = lambda project, month: (
            _cluster_report(month)
        )

        with (
            mock.patch.object(
                models.Allocation, "is_added_to_openportal", return_value=True
            ),
            mock.patch.object(
                spend_profiles,
                "add_forfeits",
                side_effect=lambda allocation, report, month, resource: report,
            ) as add_forfeits,
            mock.patch.object(
                openportal_backend.OpenPortalBackend, "_reconcile_historical_usage"
            ) as reconcile,
        ):
            backend.sync_usage(allocation)

        self.assertEqual(add_forfeits.call_count, 2)
        self.assertEqual(add_forfeits.call_args.args[3], RESOURCE)
        self.assertEqual(reconcile.call_count, 2)
