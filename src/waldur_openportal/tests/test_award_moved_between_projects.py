"""An award accepted onto a new project, then moved to one that held an earlier award.

The production case these tests are built from: award 2 arrived on 21 August
and was accepted onto a NEW project, u6vn, which minted the award's
local_identifier as "u6vn.<portal>". It should have gone to the existing
project u6ll, which had held award 1 from May to July. So on 27 August it was
detached, attached to u6ll, and u6vn was deleted.

That left three things wrong, all of which these tests pin:

- The award accounting card found its usage under local_identifier, the
  deleted u6vn's identifier, and showed zero.
- The project's credit was the award's allocation minus EVERY invoice the
  project had ever had, award 1's included, so it went to zero and the
  OpenPortal limits with it.
- The usage reported to the awarding portal counted u6ll's usage from 21
  August, when the award was not yet on it.

The fix finds each attachment's usage under that attachment's project's own
identifiers, clipped to the days of that attachment, and charges the credit
only the share of each month that fell on those days.

Dates are in 2025, wholly in the past, so no month is the current one and
"excluding the current month" never removes anything here.
"""

import datetime
import decimal
import io
from contextlib import contextmanager
from unittest import mock

from django.core.management import call_command
from django.test import TestCase

from waldur_core.structure import models as structure_models
from waldur_core.structure.tests import factories as structure_factories
from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_mastermind.invoices import models as invoice_models
from waldur_mastermind.invoices.tests import factories as invoice_factories
from waldur_openportal import models, utils

PORTAL = "testportal"
AWARD_ARRIVED = datetime.date(2025, 8, 21)
MOVED_TO_U6LL = datetime.date(2025, 8, 27)

# u6ll's daily usage: heavy under award 1 (to 26 August), lighter under
# award 2. Uneven on purpose, so a split of August by days would be wrong.
U6LL_HOURS_UNDER_AWARD_1 = 30.0
U6LL_HOURS_UNDER_AWARD_2 = 10.0


def _dt(day: datetime.date):
    return datetime.datetime(day.year, day.month, day.day, 9, tzinfo=datetime.UTC)


def _u6ll_hours(day: datetime.date) -> float:
    if day < MOVED_TO_U6LL:
        return U6LL_HOURS_UNDER_AWARD_1
    return U6LL_HOURS_UNDER_AWARD_2


def _days(start: datetime.date, end: datetime.date):
    day = start
    while day <= end:
        yield day
        day += datetime.timedelta(days=1)


def _month_hours(year, month, hours_on) -> float:
    start = datetime.date(year, month, 1)
    end = utils.get_last_day_of_month(start)
    return sum(hours_on(day) for day in _days(start, end))


@contextmanager
def _fake_openportal(hours_by_identifier):
    """
    Cached reports whose usage on any day comes from hours_by_identifier,
    keyed by the report's project_identifier, and an OpenPortal config that
    names PORTAL as this portal.
    """

    class _Usage:
        def __init__(self, hours):
            self.hours = hours

    class _Filtered:
        def __init__(self, hours):
            self.total_usage = _Usage(hours)

    class _Report:
        def __init__(self, cached):
            self.hours_on = hours_by_identifier.get(
                cached.project_identifier, lambda day: 0.0
            )
            self.month_start = datetime.date(cached.year, cached.month, 1)
            self.month_end = utils.get_last_day_of_month(self.month_start)

        def filter(self, date_range):
            start = max(date_range.start_date, self.month_start)
            end = min(date_range.end_date, self.month_end)
            return _Filtered(sum(self.hours_on(day) for day in _days(start, end)))

    class _DateRange:
        def __init__(self, start_date, end_date):
            self.start_date = start_date
            self.end_date = end_date

    with (
        mock.patch.object(
            models.CachedProjectUsageReport,
            "get_report",
            autospec=True,
            side_effect=_Report,
        ),
        mock.patch("openportal.DateRange", _DateRange),
        mock.patch("openportal.get_portal", return_value=PORTAL),
        mock.patch("waldur_openportal.config.ensure_config_loaded", return_value=True),
    ):
        yield


class AwardMovedBetweenProjectsTest(TestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.u6ll = self.fixture.project
        self.u6vn = structure_factories.ProjectFactory(customer=self.fixture.customer)
        models.ProjectInfo.objects.create(project=self.u6ll, shortname="u6ll")
        models.ProjectInfo.objects.create(project=self.u6vn, shortname="u6vn")

        # Award 2, with the identifier minted for the project it was first
        # accepted onto - and never updated when it moved.
        self.award = models.ManagedProject.objects.create(
            destination="airr.brics.isambard-ai",
            identifier="award2.airr",
            local_identifier=f"u6vn.{PORTAL}",
            project=self.u6ll,
        )
        models.ManagedProjectAttachment.objects.create(
            managed_project=self.award,
            project=self.u6vn,
            attached_at=_dt(AWARD_ARRIVED),
            detached_at=_dt(MOVED_TO_U6LL),
        )
        models.ManagedProjectAttachment.objects.create(
            managed_project=self.award,
            project=self.u6ll,
            attached_at=_dt(MOVED_TO_U6LL),
        )
        self.u6vn.delete()

        # u6ll's usage, May to October, cached under its own identifier; and
        # an empty report for the deleted u6vn, as production had.
        self.months = [(2025, month) for month in range(5, 11)]
        for year, month in self.months:
            models.CachedProjectUsageReport.objects.create(
                year=year,
                month=month,
                project_identifier=f"u6ll.{PORTAL}",
                resource="brics.aip2.clusters.shared",
                is_complete=True,
                report={},
            )
        models.CachedProjectUsageReport.objects.create(
            year=2025,
            month=8,
            project_identifier=f"u6vn.{PORTAL}",
            resource="brics.aip2.clusters.shared",
            is_complete=True,
            report={},
        )

        # u6ll's invoices: billed at one credit an hour, so each month's
        # price is that month's usage.
        for year, month in self.months:
            invoice = invoice_factories.InvoiceFactory(
                customer=self.fixture.customer, year=year, month=month
            )
            invoice_factories.InvoiceItemFactory(
                invoice=invoice,
                project=self.u6ll,
                unit_price=decimal.Decimal(str(_month_hours(year, month, _u6ll_hours))),
                quantity=1,
            )

        self.hours = {f"u6ll.{PORTAL}": _u6ll_hours}

        # Award 2's own usage: u6ll from 27 August, nothing on u6vn.
        self.award_2_hours = (
            sum(
                _u6ll_hours(day)
                for day in _days(MOVED_TO_U6LL, datetime.date(2025, 8, 31))
            )
            + _month_hours(2025, 9, _u6ll_hours)
            + _month_hours(2025, 10, _u6ll_hours)
        )
        self.lifetime_spend = sum(
            _month_hours(year, month, _u6ll_hours) for year, month in self.months
        )

    # -- The award accounting card ---------------------------------------

    def test_card_finds_the_usage_on_the_project_the_award_moved_to(self):
        with _fake_openportal(self.hours):
            hours = utils.get_award_usage_hours(self.award)

        self.assertAlmostEqual(hours, self.award_2_hours)

    def test_card_does_not_count_the_moved_to_project_before_the_move(self):
        """
        The merged windows run from 21 August; u6ll's usage from then until
        the 27th belonged to whatever it held, not to this award.
        """
        merged_from_arrival = sum(
            _u6ll_hours(day) for day in _days(AWARD_ARRIVED, datetime.date(2025, 8, 31))
        )

        with _fake_openportal(self.hours):
            hours = utils.get_award_usage_hours(self.award)

        self.assertLess(
            hours,
            merged_from_arrival
            + _month_hours(2025, 9, _u6ll_hours)
            + _month_hours(2025, 10, _u6ll_hours),
        )

    def test_card_no_longer_depends_on_local_identifier(self):
        with _fake_openportal(self.hours):
            allocation, usage = utils.get_award_usage_info(self.u6ll)

        self.assertAlmostEqual(usage, self.award_2_hours)

    # -- The project's credit --------------------------------------------

    def test_award_spend_excludes_the_earlier_award(self):
        with _fake_openportal(self.hours):
            _, spend = utils.get_project_spend_info(
                self.u6ll, include_current_month=False, award_only=True
            )

        self.assertAlmostEqual(float(spend), self.award_2_hours, places=2)

    def test_without_award_only_the_lifetime_spend_is_unchanged(self):
        with _fake_openportal(self.hours):
            _, spend = utils.get_project_spend_info(
                self.u6ll, include_current_month=False
            )

        self.assertAlmostEqual(float(spend), self.lifetime_spend, places=2)

    def test_credit_is_the_allocation_less_this_awards_spend(self):
        """The production failure: lifetime spend exceeded the allocation, so 0."""
        allocation = decimal.Decimal(1000)
        self.assertGreater(self.lifetime_spend, float(allocation))

        with _fake_openportal(self.hours):
            utils.set_project_credits(self.u6ll, allocation)

        credit = invoice_models.ProjectCredit.objects.get(project=self.u6ll)
        self.assertAlmostEqual(
            float(credit.value), float(allocation) - self.award_2_hours, places=1
        )

    def test_credit_reads_back_as_the_allocation(self):
        """
        The board compares a new allocation with get_project_credits() and
        only acts on a difference; reading back the lifetime spend made every
        such project look changed.
        """
        allocation = decimal.Decimal(1000)

        with _fake_openportal(self.hours):
            utils.set_project_credits(self.u6ll, allocation)
            read_back = utils.get_project_credits(self.u6ll)

        self.assertAlmostEqual(float(read_back), float(allocation), places=1)

    def test_a_split_month_with_no_usage_reports_counts_in_full(self):
        """
        Without usage to split August by, all of it is charged to the award:
        too little credit rather than too much.
        """
        models.CachedProjectUsageReport.objects.filter(month=8).delete()

        with _fake_openportal(self.hours):
            _, spend = utils.get_project_spend_info(
                self.u6ll, include_current_month=False, award_only=True
            )

        expected = (
            _month_hours(2025, 8, _u6ll_hours)
            + _month_hours(2025, 9, _u6ll_hours)
            + _month_hours(2025, 10, _u6ll_hours)
        )
        self.assertAlmostEqual(float(spend), expected, places=2)

    def test_a_project_with_no_award_is_charged_everything(self):
        self.award.delete()

        with _fake_openportal(self.hours):
            _, spend = utils.get_project_spend_info(
                self.u6ll, include_current_month=False, award_only=True
            )

        self.assertAlmostEqual(float(spend), self.lifetime_spend, places=2)

    # -- The usage reported to the awarding portal -----------------------

    def test_reported_days_are_those_the_award_spent_on_the_reporting_project(self):
        with _fake_openportal(self.hours):
            ranges = utils.get_managed_project_attached_date_ranges(
                self.award,
                datetime.date(2025, 8, 1),
                datetime.date(2025, 8, 31),
                self.u6ll,
            )

        self.assertEqual(ranges, [(MOVED_TO_U6LL, datetime.date(2025, 8, 31))])

    def test_reported_days_without_a_project_are_every_attached_day(self):
        with _fake_openportal(self.hours):
            ranges = utils.get_managed_project_attached_date_ranges(
                self.award, datetime.date(2025, 8, 1), datetime.date(2025, 8, 31)
            )

        self.assertEqual(ranges, [(AWARD_ARRIVED, datetime.date(2025, 8, 31))])


class AwardShareOfMonthTest(TestCase):
    identifiers = {f"p.{PORTAL}"}

    def _cache(self, month):
        models.CachedProjectUsageReport.objects.create(
            year=2025,
            month=month,
            project_identifier=f"p.{PORTAL}",
            resource="r",
            is_complete=True,
            report={},
        )

    def test_month_outside_every_window_is_zero(self):
        with _fake_openportal({}):
            share = utils._award_share_of_month(
                [(datetime.date(2025, 6, 1), None)], self.identifiers, 2025, 5
            )

        self.assertEqual(share, 0)

    def test_month_wholly_inside_a_window_is_one(self):
        with _fake_openportal({}):
            share = utils._award_share_of_month(
                [(datetime.date(2025, 4, 15), None)], self.identifiers, 2025, 5
            )

        self.assertEqual(share, 1)

    def test_split_month_is_split_by_usage_not_by_days(self):
        self._cache(5)
        # 3 hours a day to the 20th, 1 hour a day after: 60 + 11 = 71 hours.
        hours = {f"p.{PORTAL}": lambda day: 3.0 if day.day <= 20 else 1.0}

        with _fake_openportal(hours):
            share = utils._award_share_of_month(
                [(datetime.date(2025, 5, 21), None)], self.identifiers, 2025, 5
            )

        self.assertAlmostEqual(float(share), 11 / 71, places=6)

    def test_split_month_with_no_usage_counts_in_full(self):
        self._cache(5)

        with _fake_openportal({}):
            share = utils._award_share_of_month(
                [(datetime.date(2025, 5, 21), None)], self.identifiers, 2025, 5
            )

        self.assertEqual(share, 1)


class LocalIdentifierFollowsTheProjectTest(TestCase):
    """
    ManagedProject.local_identifier names the project the award is attached
    to. It was minted once, for the first project, and kept naming that one
    after the award moved - to u6vn, after u6vn had been deleted.
    """

    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.u6ll = self.fixture.project
        self.u6vn = structure_factories.ProjectFactory(customer=self.fixture.customer)
        models.ProjectInfo.objects.create(project=self.u6ll, shortname="u6ll")
        models.ProjectInfo.objects.create(project=self.u6vn, shortname="u6vn")
        self.award = models.ManagedProject.objects.create(
            destination="airr.brics.isambard-ai",
            identifier="award2.airr",
            local_identifier=f"u6vn.{PORTAL}",
            project=self.u6vn,
        )
        # set_project also rewrites the award's project link in its details,
        # which needs a real AwardDetails; that is not what is under test.
        for name, value in (
            ("get_details", mock.Mock()),
            ("set_details", None),
            ("_get_project_link", None),
        ):
            patcher = mock.patch.object(models.ManagedProject, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_moving_the_award_renames_it_after_the_new_project(self):
        with _fake_openportal({}):
            self.award.set_project(None)
            self.award.set_project(self.u6ll)

        self.award.refresh_from_db()
        self.assertEqual(self.award.local_identifier, f"u6ll.{PORTAL}")

    def test_moving_straight_from_one_project_to_another(self):
        with _fake_openportal({}):
            self.award.set_project(self.u6ll)

        self.award.refresh_from_db()
        self.assertEqual(self.award.local_identifier, f"u6ll.{PORTAL}")

    def test_detaching_keeps_the_last_identifier(self):
        with _fake_openportal({}):
            self.award.set_project(None)

        self.award.refresh_from_db()
        self.assertEqual(self.award.local_identifier, f"u6vn.{PORTAL}")

    def test_moving_to_a_project_with_no_shortname_clears_it(self):
        """
        Left alone it would name the project the award has left; cleared,
        the board mints the new project's when it next needs one.
        """
        no_shortname = structure_factories.ProjectFactory(
            customer=self.fixture.customer
        )

        with _fake_openportal({}):
            self.award.set_project(no_shortname)

        self.award.refresh_from_db()
        self.assertIsNone(self.award.local_identifier)

    def test_same_project_without_the_config_keeps_its_identifier(self):
        with mock.patch(
            "waldur_openportal.config.ensure_config_loaded", return_value=False
        ):
            self.award.set_project(self.u6vn)

        self.award.refresh_from_db()
        self.assertEqual(self.award.local_identifier, f"u6vn.{PORTAL}")


class AwardStartDateTest(AwardMovedBetweenProjectsTest):
    """
    An award counts from its own start_date when that is before it reached
    this portal: a renewal approved on the awarding portal some days after it
    started.
    """

    def _set_start(self, start):
        models.ManagedProject.objects.filter(pk=self.award.pk).update(
            details={"start_date": start}
        )
        self.award.refresh_from_db()

    def test_spend_counts_from_an_earlier_award_start(self):
        self._set_start(AWARD_ARRIVED.isoformat())

        with _fake_openportal(self.hours):
            _, spend = utils.get_project_spend_info(
                self.u6ll, include_current_month=False, award_only=True
            )

        # u6ll from 21 August, not 27: six more days at award 1's rate.
        expected = (
            sum(
                _u6ll_hours(day)
                for day in _days(AWARD_ARRIVED, datetime.date(2025, 8, 31))
            )
            + _month_hours(2025, 9, _u6ll_hours)
            + _month_hours(2025, 10, _u6ll_hours)
        )
        self.assertAlmostEqual(float(spend), expected, places=2)

    def test_card_counts_from_an_earlier_award_start(self):
        self._set_start(AWARD_ARRIVED.isoformat())

        with _fake_openportal(self.hours):
            hours = utils.get_award_usage_hours(self.award)

        self.assertAlmostEqual(
            hours,
            self.award_2_hours
            + sum(
                _u6ll_hours(day)
                for day in _days(AWARD_ARRIVED, MOVED_TO_U6LL - datetime.timedelta(1))
            ),
        )

    def test_a_later_award_start_does_not_shorten_the_attachment(self):
        self._set_start("2025-09-15")

        with _fake_openportal(self.hours):
            _, spend = utils.get_project_spend_info(
                self.u6ll, include_current_month=False, award_only=True
            )

        self.assertAlmostEqual(float(spend), self.award_2_hours, places=2)

    def test_reports_to_the_awarding_portal_still_follow_the_attachments(self):
        self._set_start(AWARD_ARRIVED.isoformat())

        with _fake_openportal(self.hours):
            ranges = utils.get_managed_project_attached_date_ranges(
                self.award,
                datetime.date(2025, 8, 1),
                datetime.date(2025, 8, 31),
                self.u6ll,
            )

        self.assertEqual(ranges, [(MOVED_TO_U6LL, datetime.date(2025, 8, 31))])

    def test_an_unreadable_start_date_is_ignored(self):
        self._set_start("not a date")

        with _fake_openportal(self.hours):
            _, spend = utils.get_project_spend_info(
                self.u6ll, include_current_month=False, award_only=True
            )

        self.assertAlmostEqual(float(spend), self.award_2_hours, places=2)


class BackfillManagedProjectAttachmentsTest(TestCase):
    """
    Awards whose records predate the audit log are taken to have been on their
    project since it started.
    """

    AUDIT_START = datetime.datetime(2026, 6, 4, 9, tzinfo=datetime.UTC)

    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        self.project.start_date = datetime.date(2025, 3, 1)
        self.project.save(update_fields=["start_date"])

        # The first audit entry anywhere marks when recording began.
        self.other = models.ManagedProject.objects.create(
            destination="d", identifier="other.airr", project=None
        )
        self._audit(self.other, self.AUDIT_START)

        self.legacy = models.ManagedProject.objects.create(
            destination="d", identifier="legacy.airr", project=self.project
        )
        self._created(self.legacy, datetime.datetime(2025, 10, 24, tzinfo=datetime.UTC))

    def _audit(self, managed_project, when):
        entry = models.ManagedProjectAuditEntry.objects.create(
            identifier=managed_project.identifier,
            destination=managed_project.destination,
            managed_project=managed_project,
            event_type=models.ManagedProjectAuditEventType.CREATED,
        )
        models.ManagedProjectAuditEntry.objects.filter(pk=entry.pk).update(
            timestamp=when
        )

    def _created(self, managed_project, when):
        models.ManagedProject.objects.filter(pk=managed_project.pk).update(created=when)
        managed_project.refresh_from_db()

    def _first_attached(self, managed_project):
        return utils.timezone.localdate(
            managed_project.get_attachments()
            .order_by("attached_at")
            .first()
            .attached_at
        )

    def test_legacy_award_is_attached_from_its_project_start(self):
        summary = utils.backfill_managed_project_attachments()

        self.assertEqual(summary["first attachments backdated"], 1)
        self.assertEqual(self._first_attached(self.legacy), datetime.date(2025, 3, 1))

    def test_project_created_date_stands_in_for_a_missing_start_date(self):
        self.project.start_date = None
        self.project.save(update_fields=["start_date"])
        structure_models.Project.objects.filter(pk=self.project.pk).update(
            created=datetime.datetime(2025, 2, 11, 12, tzinfo=datetime.UTC)
        )

        utils.backfill_managed_project_attachments()

        self.assertEqual(self._first_attached(self.legacy), datetime.date(2025, 2, 11))

    def test_a_legacy_audit_entry_explains_it(self):
        utils.backfill_managed_project_attachments()

        entry = models.ManagedProjectAuditEntry.objects.get(
            managed_project=self.legacy, note=utils.LEGACY_ATTACHMENT_NOTE
        )
        self.assertEqual(
            entry.event_type, models.ManagedProjectAuditEventType.PROJECT_ATTACHED
        )
        self.assertEqual(entry.timestamp.date(), datetime.date(2025, 3, 1))

    def test_award_created_after_the_audit_log_began_is_left_alone(self):
        recent = models.ManagedProject.objects.create(
            destination="d",
            identifier="recent.airr",
            project=structure_factories.ProjectFactory(customer=self.fixture.customer),
        )
        self._created(recent, datetime.datetime(2026, 9, 9, tzinfo=datetime.UTC))
        before = self._first_attached(recent)

        utils.backfill_managed_project_attachments()

        self.assertEqual(self._first_attached(recent), before)
        self.assertFalse(
            models.ManagedProjectAuditEntry.objects.filter(
                managed_project=recent, note=utils.LEGACY_ATTACHMENT_NOTE
            ).exists()
        )

    def test_an_award_whose_first_attachment_is_elsewhere_is_left_alone(self):
        elsewhere = structure_factories.ProjectFactory(customer=self.fixture.customer)
        models.ManagedProjectAttachment.objects.create(
            managed_project=self.legacy,
            project=elsewhere,
            attached_at=datetime.datetime(2025, 10, 24, tzinfo=datetime.UTC),
            detached_at=datetime.datetime(2025, 11, 1, tzinfo=datetime.UTC),
        )
        models.ManagedProjectAttachment.objects.create(
            managed_project=self.legacy,
            project=self.project,
            attached_at=datetime.datetime(2025, 11, 1, tzinfo=datetime.UTC),
        )

        summary = utils.backfill_managed_project_attachments()

        self.assertEqual(summary["skipped: first attachment is to another project"], 1)
        self.assertEqual(self._first_attached(self.legacy), datetime.date(2025, 10, 24))

    def test_a_second_run_changes_nothing(self):
        utils.backfill_managed_project_attachments()

        summary = utils.backfill_managed_project_attachments()

        self.assertEqual(summary["first attachments backdated"], 0)
        self.assertEqual(summary["legacy audit entries recorded"], 0)
        self.assertEqual(summary["awards predating the audit log"], 1)

    def test_dry_run_writes_nothing(self):
        self.legacy.get_attachments()  # the reconstruction a live read makes
        before = self._first_attached(self.legacy)

        summary = utils.backfill_managed_project_attachments(dry_run=True)

        self.assertEqual(summary["first attachments backdated"], 1)
        self.assertEqual(self._first_attached(self.legacy), before)
        self.assertFalse(
            models.ManagedProjectAuditEntry.objects.filter(
                note=utils.LEGACY_ATTACHMENT_NOTE
            ).exists()
        )

    def test_no_audit_log_at_all_changes_nothing(self):
        models.ManagedProjectAuditEntry.objects.all().delete()

        summary = utils.backfill_managed_project_attachments()

        self.assertEqual(summary["first attachments backdated"], 0)

    def test_command_dry_run_reports_and_rolls_back(self):
        out = io.StringIO()

        call_command("backfill_managed_project_attachments", "--dry-run", stdout=out)

        self.assertIn("first attachments backdated", out.getvalue())
        self.assertIn("Dry run: nothing changed.", out.getvalue())
        self.assertFalse(
            models.ManagedProjectAuditEntry.objects.filter(
                note=utils.LEGACY_ATTACHMENT_NOTE
            ).exists()
        )
