"""The site side of an award's spend profile: kept with the award, the features
this portal answers that it supports, and the read-only progress per period.

The award: 1000 NHR over 2027, used at a steady 2 NHR a day from its start,
with a profile of a quarter a quarter from April (January to March are
uncontrolled).
"""

import datetime
import json
import unittest
from unittest import mock

import openportal
from django.test import TestCase
from rest_framework import test

from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import models, spend_profiles, tasks, utils
from waldur_openportal.tests.test_award_moved_between_projects import (
    PORTAL,
    _fake_openportal,
)

needs_spend_profiles = unittest.skipUnless(
    spend_profiles.is_supported(), "needs openportal 0.94 (spend profiles)"
)

START = datetime.date(2027, 1, 1)
HOURS_PER_DAY = 2.0
PROFILE = [
    {"from": "2027-04-01", "minimum": "200 NHR", "maximum": "250 NHR"},
    {"from": "2027-07-01", "maximum": "250 NHR"},
    {"from": "2027-10-01", "minimum": "100 NHR"},
]
AWARD = {
    "name": "Award",
    "start_date": "2027-01-01",
    "end_date": "2027-12-31",
    "allocation": "1000 NHR",
    "spend_profile": PROFILE,
}


def _hours(day: datetime.date) -> float:
    return HOURS_PER_DAY if day >= START else 0.0


def _days(start, end) -> int:
    return (end - start).days + 1


@needs_spend_profiles
class SpendProfileKeptWithAwardTest(TestCase):
    def setUp(self):
        self.managed_project = models.ManagedProject.objects.create(
            destination="airr.brics.isambard-ai",
            identifier="award.airr",
            project=structure_fixtures.ProjectFixture().project,
            details=AWARD,
        )

    def _merge(self, **fields):
        incoming = openportal.AwardDetails(json.dumps(fields))
        return json.loads(str(self.managed_project.merge_details(incoming)))

    def test_an_update_without_a_profile_keeps_it(self):
        merged = self._merge(name="Award")
        self.assertEqual(merged["spend_profile"], PROFILE)

    def test_an_update_with_a_profile_replaces_it(self):
        new = [{"from": "2027-04-01", "maximum": "500 NHR"}]
        merged = self._merge(name="Award", spend_profile=new)
        self.assertEqual(merged["spend_profile"], new)


class FeatureDiscoveryTest(TestCase):
    """What run_job answers an awarding portal asking about features."""

    def _run(self, command, *arguments):
        job_model = models.Job.objects.create(
            job_id=f"job-{models.Job.objects.count()}", state=models.Job.State.PENDING
        )
        job = mock.Mock()
        job.state = "pending"
        job.forwarded_for = None
        job.instruction.command = command
        job.instruction.arguments = list(arguments)
        job.completed.return_value.to_json.return_value = "{}"
        with (
            mock.patch.object(models.Job, "get_job", return_value=job),
            mock.patch.object(
                tasks.openportal.Status, "pending", return_value="pending"
            ),
            mock.patch.object(tasks, "OpenPortalBoard"),
        ):
            tasks.run_job(job_model)
        job.completed.assert_called_once()
        return job.completed.call_args.args[0]

    def test_no_feature_is_claimed_until_it_is_enforced(self):
        with mock.patch.object(spend_profiles, "SUPPORTED_FEATURES", frozenset()):
            self.assertIs(
                self._run("is_feature_supported", spend_profiles.AWARD_SPEND_MAXIMUMS),
                False,
            )
            self.assertEqual(self._run("get_supported_features"), [])

    def test_a_claimed_feature_is_answered(self):
        features = frozenset(
            {spend_profiles.AWARD_SPEND_MINIMUMS, spend_profiles.AWARD_SPEND_MAXIMUMS}
        )
        with mock.patch.object(spend_profiles, "SUPPORTED_FEATURES", features):
            self.assertIs(
                self._run("is_feature_supported", spend_profiles.AWARD_SPEND_MAXIMUMS),
                True,
            )
            self.assertIs(self._run("is_feature_supported", "no_such_feature"), False)
            self.assertEqual(
                self._run("get_supported_features"),
                sorted(features),
            )


class _AwardWithUsage(TestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        models.ProjectInfo.objects.create(project=self.project, shortname="sp01")
        self.managed_project = models.ManagedProject.objects.create(
            destination="airr.brics.isambard-ai",
            identifier="award.airr",
            local_identifier=f"sp01.{PORTAL}",
            project=self.project,
            details=AWARD,
        )
        models.ManagedProjectAttachment.objects.create(
            managed_project=self.managed_project,
            project=self.project,
            attached_at=datetime.datetime(2027, 1, 1, 9, tzinfo=datetime.UTC),
        )
        for month in range(1, 13):
            models.CachedProjectUsageReport.objects.create(
                year=2027,
                month=month,
                project_identifier=f"sp01.{PORTAL}",
                resource="brics.aip2.clusters.shared",
                is_complete=True,
                report={},
            )

    def usage(self):
        return _fake_openportal({f"sp01.{PORTAL}": _hours})


class AwardUsageBetweenDatesTest(_AwardWithUsage):
    def test_counts_only_the_days_asked_for(self):
        with self.usage():
            hours = utils.get_award_usage_hours(
                self.managed_project,
                range_start=datetime.date(2027, 4, 1),
                range_end=datetime.date(2027, 4, 30),
            )
        self.assertAlmostEqual(hours, 30 * HOURS_PER_DAY)

    def test_up_to_a_day(self):
        with self.usage():
            hours = utils.get_award_usage_hours(
                self.managed_project, range_end=datetime.date(2027, 1, 10)
            )
        self.assertAlmostEqual(hours, 10 * HOURS_PER_DAY)

    def test_a_range_before_the_award_is_nothing(self):
        with self.usage():
            hours = utils.get_award_usage_hours(
                self.managed_project, range_end=datetime.date(2026, 12, 31)
            )
        self.assertEqual(hours, 0.0)


@needs_spend_profiles
class SpendProgressTest(_AwardWithUsage):
    TODAY = datetime.date(2027, 8, 15)

    def progress(self, today=None):
        with self.usage():
            return spend_profiles.progress(self.managed_project, today or self.TODAY)

    def test_no_profile_no_progress(self):
        details = dict(AWARD)
        del details["spend_profile"]
        self.managed_project.details = details
        self.managed_project.save()
        self.assertIsNone(spend_profiles.progress(self.managed_project, self.TODAY))

    def test_periods_and_their_spend(self):
        result = self.progress()
        self.assertEqual(result["units"], "NHR")
        self.assertEqual(result["allocation"], 1000.0)
        self.assertAlmostEqual(
            result["spend"], _days(START, self.TODAY) * HOURS_PER_DAY
        )

        april, july, october = result["periods"]
        self.assertEqual(april["from"], datetime.date(2027, 4, 1))
        self.assertEqual(april["to"], datetime.date(2027, 6, 30))
        self.assertEqual(october["to"], datetime.date(2027, 12, 31))
        self.assertEqual(
            [p["status"] for p in result["periods"]], ["ended", "current", "upcoming"]
        )

        self.assertAlmostEqual(april["spend"], 91 * HOURS_PER_DAY)
        self.assertAlmostEqual(
            april["cumulative_spend"],
            _days(START, datetime.date(2027, 6, 30)) * HOURS_PER_DAY,
        )
        self.assertAlmostEqual(
            july["spend"], _days(datetime.date(2027, 7, 1), self.TODAY) * HOURS_PER_DAY
        )
        self.assertIsNone(october["spend"])
        self.assertIsNone(october["headroom"])
        self.assertIsNone(april["forfeit"])

    def test_caps_add_up_the_maximums_after_the_uncontrolled_start(self):
        april, july, october = self.progress()["periods"]
        before = _days(START, datetime.date(2027, 3, 31)) * HOURS_PER_DAY

        # The first quarter was uncontrolled and counts at what it charged.
        self.assertAlmostEqual(april["cap"], before + 250)
        self.assertAlmostEqual(july["cap"], before + 500)
        # No maximum: the whole award.
        self.assertEqual(october["cap"], 1000.0)
        self.assertAlmostEqual(july["headroom"], july["cap"] - july["cumulative_spend"])

    def test_minimums_accumulate(self):
        april, july, october = self.progress()["periods"]
        self.assertEqual(april["cumulative_minimum"], 200.0)
        self.assertEqual(july["cumulative_minimum"], 200.0)
        self.assertEqual(october["cumulative_minimum"], 300.0)

    def test_a_cap_never_exceeds_the_award(self):
        details = dict(AWARD, allocation="400 NHR")
        self.managed_project.details = details
        self.managed_project.save()
        _, july, _ = self.progress()["periods"]
        self.assertEqual(july["cap"], 400.0)

    def test_amounts_are_in_the_award_units(self):
        """Usage is node-hours; an award in GPU hours is charged through the
        project template's factor, as its credits are."""
        self.managed_project.project_template = models.ProjectTemplate.objects.create(
            name="gpu",
            portal="testportal",
            allocation_units_mapping={"GPUHR": 4.0},
        )
        details = dict(
            AWARD,
            allocation="4000 GPUHR",
            spend_profile=[{"from": "2027-04-01", "maximum": "1000 GPUHR"}],
        )
        self.managed_project.details = details
        self.managed_project.save()
        result = self.progress()
        self.assertEqual(result["units"], "GPUHR")
        self.assertAlmostEqual(
            result["spend"], _days(START, self.TODAY) * HOURS_PER_DAY * 4
        )
        (april,) = result["periods"]
        self.assertAlmostEqual(
            april["cap"],
            _days(START, datetime.date(2027, 3, 31)) * HOURS_PER_DAY * 4 + 1000,
        )


@needs_spend_profiles
class SpendProgressApiTest(_AwardWithUsage):
    url = "/api/openportal-managed-project-accounting-summary/"

    def test_project_members_see_the_progress(self):
        client = test.APIClient()
        client.force_authenticate(self.fixture.member)
        with (
            self.usage(),
            mock.patch.object(
                spend_profiles.timezone,
                "now",
                return_value=datetime.datetime(2027, 8, 15, 12, tzinfo=datetime.UTC),
            ),
        ):
            response = client.get(f"{self.url}{self.project.uuid}/")
        self.assertEqual(response.status_code, 200, response.data)
        spend_profile = response.json()["spend_profile"]
        self.assertEqual(spend_profile["units"], "NHR")
        self.assertEqual(
            [p["status"] for p in spend_profile["periods"]],
            ["ended", "current", "upcoming"],
        )
        self.assertEqual(spend_profile["periods"][0]["from"], "2027-04-01")

    def test_an_award_without_a_profile_has_none(self):
        details = dict(AWARD)
        del details["spend_profile"]
        self.managed_project.details = details
        self.managed_project.save()
        client = test.APIClient()
        client.force_authenticate(self.fixture.staff)
        with self.usage():
            response = client.get(f"{self.url}{self.project.uuid}/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIsNone(response.data["spend_profile"])


@needs_spend_profiles
class WithheldCreditsTest(_AwardWithUsage):
    def withheld(self, today):
        with self.usage():
            return spend_profiles.withheld_credits(self.managed_project, today)

    def test_a_period_with_a_maximum_withholds_the_award_above_its_cap(self):
        # July's cap: January to March at what they charged, plus two
        # maximums of 250.
        before = _days(START, datetime.date(2027, 3, 31)) * HOURS_PER_DAY
        self.assertAlmostEqual(
            self.withheld(datetime.date(2027, 8, 15)), 1000 - (before + 500)
        )

    def test_nothing_is_withheld_outside_a_capped_period(self):
        for today in (
            datetime.date(2027, 2, 1),  # before the first period
            datetime.date(2027, 11, 1),  # a period with no maximum
            datetime.date(2028, 1, 5),  # after the award
        ):
            self.assertEqual(self.withheld(today), 0.0, today)

    def test_nothing_is_withheld_unless_maximums_are_claimed(self):
        with mock.patch.object(spend_profiles, "SUPPORTED_FEATURES", frozenset()):
            self.assertEqual(self.withheld(datetime.date(2027, 8, 15)), 0.0)

    def test_withheld_in_credits(self):
        self.managed_project.project_template = models.ProjectTemplate.objects.create(
            name="gpu", portal="testportal", allocation_units_mapping={"GPUHR": 4.0}
        )
        self.managed_project.details = dict(
            AWARD,
            allocation="4000 GPUHR",
            spend_profile=[{"from": "2027-04-01", "maximum": "1000 GPUHR"}],
        )
        self.managed_project.save()
        before = _days(START, datetime.date(2027, 3, 31)) * HOURS_PER_DAY * 4
        self.assertAlmostEqual(
            self.withheld(datetime.date(2027, 5, 1)), (4000 - (before + 1000)) / 4
        )


class LimitSyncWithholdsTest(TestCase):
    """sync_allocation_limits takes what the profile withholds off the limit,
    and leaves the project's credits alone."""

    def setUp(self):
        self.project = structure_fixtures.ProjectFixture().project
        self.managed_project = models.ManagedProject.objects.create(
            destination="airr.brics.isambard-ai",
            identifier="award.airr",
            project=self.project,
            details=AWARD,
        )

    def _sync(self, credit_value, withheld, node_usage=0.0):
        credit = mock.MagicMock(project=self.project, value=credit_value)
        credits_qs = mock.MagicMock()
        credits_qs.__iter__ = mock.Mock(return_value=iter([credit]))
        allocation = mock.MagicMock(node_usage=node_usage, node_limit=0)
        allocation.is_added_to_openportal.return_value = True
        with (
            mock.patch.object(tasks.config, "ensure_config_loaded", return_value=True),
            mock.patch.object(
                tasks.models.OnceTask.objects,
                "get_or_create",
                return_value=(mock.MagicMock(last_run=None), True),
            ),
            mock.patch.object(
                tasks.invoice_models.ProjectCredit.objects,
                "select_related",
                return_value=credits_qs,
            ),
            mock.patch.object(
                tasks.models.Allocation.objects, "filter", return_value=[allocation]
            ),
            mock.patch.object(
                spend_profiles, "withheld_credits", return_value=withheld
            ) as withheld_credits,
        ):
            tasks.sync_allocation_limits()
        return allocation, withheld_credits

    def test_the_limit_is_the_cap(self):
        allocation, withheld_credits = self._sync(800, 320.0)
        withheld_credits.assert_called_once()
        self.assertAlmostEqual(allocation.node_limit, 480.0)
        allocation.get_backend.return_value.set_resource_limits.assert_called_once()

    def test_spend_past_the_cap_stops_the_project(self):
        allocation, _ = self._sync(800, 320.0, node_usage=500.0)
        self.assertEqual(allocation.node_limit, 0)

    def test_without_a_cap_the_limit_is_the_credits(self):
        allocation, _ = self._sync(800, 0.0)
        self.assertAlmostEqual(allocation.node_limit, 800.0)
