"""Usage reports say which unit they are in (openportal 0.95).

Every report cached before then was time: node-seconds on a site, the
award's unit at 3600 per hour on an awarding portal. They are declared so
as they are read, and the site's report to the awarding portal is converted
to, and labelled in, the award's unit.
"""

import datetime
import json
from unittest import mock

import openportal
from django.test import TestCase

from waldur_core.structure.tests import factories as structure_factories
from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import models
from waldur_openportal.board import OpenPortalBoard

PORTAL = "testportal"
IDENTIFIER = f"sp01.{PORTAL}"
DESTINATION = "airr.brics.isambard-ai"


def _report_json(month_start, days, hours_per_day, unit="NHR", legacy=True):
    """A month's report; legacy=True leaves the unit out, as cached before
    reports carried one."""
    report = openportal.ProjectUsageReport(
        openportal.ProjectIdentifier(IDENTIFIER), unit=openportal.UsageUnit(unit)
    )
    for offset in range(days):
        daily = openportal.DailyProjectUsageReport()
        daily.add_unattributed_usage(openportal.Usage.from_hours(hours_per_day))
        daily.set_complete()
        report.add_report(month_start + datetime.timedelta(days=offset), daily)
    data = json.loads(report.to_json())
    if legacy:
        data.pop("usage_unit", None)
    return data


class UnitNamesTest(TestCase):
    def test_units_are_canonical(self):
        self.assertEqual(models.usage_unit_name("node hours"), "NHR")
        self.assertEqual(models.usage_unit_name("GPUHR"), "GPUHR")
        self.assertEqual(models.usage_unit_name("gbp"), "GBP")
        self.assertEqual(models.usage_unit_name("not a unit"), "NHR")


class CachedReportUnitTest(TestCase):
    def cached(self, **kwargs):
        return models.CachedProjectUsageReport(
            year=2027,
            month=3,
            project_identifier=IDENTIFIER,
            resource=DESTINATION,
            report=_report_json(datetime.date(2027, 3, 1), 2, 1.0, **kwargs),
        )

    def test_a_report_from_before_units_is_node_hours_by_default(self):
        report = self.cached().get_report()
        self.assertEqual(report.unit.name, "NHR")
        self.assertAlmostEqual(report.total().value, 2.0)

    def test_or_the_unit_it_is_read_in(self):
        self.assertEqual(self.cached().get_report("GPUHR").unit.name, "GPUHR")

    def test_a_currency_award_declares_old_reports_as_node_hours(self):
        """Every report from before units was time, so a currency cannot
        describe one."""
        self.assertEqual(self.cached().get_report("GBP").unit.name, "NHR")

    def test_a_report_with_a_unit_keeps_it(self):
        report = self.cached(unit="GPUHR", legacy=False).get_report("NHR")
        self.assertEqual(report.unit.name, "GPUHR")

    def test_months_from_before_and_after_units_combine(self):
        old = self.cached().get_report()
        new = self.cached(legacy=False).get_report()
        self.assertAlmostEqual(
            openportal.ProjectUsageReport.combine([old, new]).total().value, 4.0
        )


class SiteReportIsInTheAwardsUnitTest(TestCase):
    """The site's usage report, built from the cluster's node-hours, reaches
    the awarding portal converted to and labelled in the award's unit."""

    def setUp(self):
        for patcher in (
            mock.patch(
                "waldur_openportal.config.ensure_config_loaded", return_value=True
            ),
            mock.patch("openportal.get_portal", return_value=PORTAL),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        fixture = structure_fixtures.ProjectFixture()
        self.project = fixture.project
        models.ProjectInfo.objects.create(project=self.project, shortname="sp01")
        models.Allocation.objects.create(
            name="cluster",
            project=self.project,
            service_settings=structure_factories.ServiceSettingsFactory(
                customer=fixture.customer
            ),
            backend_id=IDENTIFIER,
        )
        template = models.ProjectTemplate.objects.create(
            name="gpu", portal=PORTAL, allocation_units_mapping={"GPUHR": 4.0}
        )
        self.managed_project = models.ManagedProject.objects.create(
            destination=DESTINATION,
            identifier="award.airr",
            local_identifier=IDENTIFIER,
            project=self.project,
            project_template=template,
            details={
                "name": "Award",
                "start_date": "2027-01-01",
                "end_date": "2027-12-31",
                "allocation": "4000 GPUHR",
            },
        )
        models.ManagedProjectAttachment.objects.create(
            managed_project=self.managed_project,
            project=self.project,
            attached_at=datetime.datetime(2027, 1, 1, 9, tzinfo=datetime.UTC),
        )
        models.CachedProjectUsageReport.objects.create(
            year=2027,
            month=3,
            project_identifier=IDENTIFIER,
            resource="brics.aip2.clusters.shared",
            is_complete=True,
            report=_report_json(datetime.date(2027, 3, 1), 31, 1.0),
        )

    def test_the_report_is_in_gpu_hours(self):
        report = OpenPortalBoard(DESTINATION).get_usage_report(
            openportal.ProjectIdentifier("award.airr"),
            openportal.DateRange(datetime.date(2027, 3, 1), datetime.date(2027, 3, 31)),
        )
        self.assertEqual(report.unit.name, "GPUHR")
        self.assertAlmostEqual(report.total().value, 31 * 4.0)
