import datetime

from django.test import TestCase
from freezegun import freeze_time

from waldur_core.structure.filters import ProjectFilter
from waldur_core.structure.models import Project
from waldur_core.structure.tests import factories

TODAY = datetime.date(2026, 6, 15)


def filtered_uuids(**query):
    """Run ProjectFilter over all projects and return the matching UUIDs."""
    project_filter = ProjectFilter(query, queryset=Project.objects.all())
    assert project_filter.is_valid(), project_filter.errors
    return {p.uuid for p in project_filter.qs}


class ProjectDateFilterTest(TestCase):
    """Coverage for the project date filters used by the homeport dashboards."""

    def setUp(self):
        self.customer = factories.CustomerFactory()

    def _project(self, name, start_date=None, end_date=None, grace_period_days=None):
        return factories.ProjectFactory(
            customer=self.customer,
            name=name,
            start_date=start_date,
            end_date=end_date,
            grace_period_days=grace_period_days,
        )

    def test_start_and_end_date_bounds(self):
        early = self._project("early", start_date=datetime.date(2026, 1, 1))
        late = self._project("late", start_date=datetime.date(2026, 12, 1))

        self.assertEqual(filtered_uuids(start_date_after="2026-06-01"), {late.uuid})
        self.assertEqual(filtered_uuids(start_date_before="2026-06-01"), {early.uuid})

        closing = self._project("closing", end_date=datetime.date(2026, 3, 1))
        self.assertEqual(filtered_uuids(end_date_before="2026-06-01"), {closing.uuid})
        self.assertEqual(filtered_uuids(end_date_after="2026-06-01"), set())

    @freeze_time(TODAY.isoformat())
    def test_started_filter_treats_unset_start_date_as_started(self):
        past = self._project("past", start_date=TODAY - datetime.timedelta(days=1))
        unset = self._project("unset", start_date=None)
        future = self._project("future", start_date=TODAY + datetime.timedelta(days=1))

        self.assertEqual(filtered_uuids(started=True), {past.uuid, unset.uuid})
        self.assertEqual(filtered_uuids(started=False), {future.uuid})

    @freeze_time(TODAY.isoformat())
    def test_ended_filter_treats_unset_end_date_as_not_ended(self):
        ended = self._project("ended", end_date=TODAY - datetime.timedelta(days=1))
        unset = self._project("unset", end_date=None)
        future = self._project("future", end_date=TODAY + datetime.timedelta(days=1))

        self.assertEqual(filtered_uuids(ended=True), {ended.uuid})
        self.assertEqual(filtered_uuids(ended=False), {unset.uuid, future.uuid})


class ProjectInGraceFilterTest(TestCase):
    """The in_grace filter resolves each project's own grace period in the
    database, mirroring Project.get_grace_period_days(): the project's own
    value, else the customer's, else zero.
    """

    def setUp(self):
        self.customer = factories.CustomerFactory(grace_period_days=None)

    def _project(self, name, end_date, grace_period_days=None):
        return factories.ProjectFactory(
            customer=self.customer,
            name=name,
            end_date=end_date,
            grace_period_days=grace_period_days,
        )

    @freeze_time(TODAY.isoformat())
    def test_uses_project_grace_period(self):
        # Ended 10 days ago with a 30 day grace period: still inside it.
        inside = self._project(
            "inside", end_date=TODAY - datetime.timedelta(days=10), grace_period_days=30
        )
        # Ended 10 days ago with a 5 day grace period: past it.
        outside = self._project(
            "outside", end_date=TODAY - datetime.timedelta(days=10), grace_period_days=5
        )

        self.assertEqual(filtered_uuids(in_grace=True), {inside.uuid})
        self.assertEqual(filtered_uuids(in_grace=False), {outside.uuid})

    @freeze_time(TODAY.isoformat())
    def test_falls_back_to_customer_grace_period(self):
        self.customer.grace_period_days = 30
        self.customer.save(update_fields=["grace_period_days"])

        inherited = self._project(
            "inherited",
            end_date=TODAY - datetime.timedelta(days=10),
            grace_period_days=None,
        )
        # A project-level zero overrides the customer's 30.
        overridden = self._project(
            "overridden",
            end_date=TODAY - datetime.timedelta(days=10),
            grace_period_days=0,
        )

        self.assertEqual(filtered_uuids(in_grace=True), {inherited.uuid})
        self.assertEqual(filtered_uuids(in_grace=False), {overridden.uuid})

    @freeze_time(TODAY.isoformat())
    def test_no_grace_period_anywhere_means_never_in_grace(self):
        self._project(
            "ended", end_date=TODAY - datetime.timedelta(days=1), grace_period_days=None
        )

        self.assertEqual(filtered_uuids(in_grace=True), set())

    @freeze_time(TODAY.isoformat())
    def test_grace_period_boundaries_are_inclusive(self):
        grace_days = 30
        # Last day of the grace period: end_date + grace_days == today.
        last_day = self._project(
            "last_day",
            end_date=TODAY - datetime.timedelta(days=grace_days),
            grace_period_days=grace_days,
        )
        # One day past it.
        just_past = self._project(
            "just_past",
            end_date=TODAY - datetime.timedelta(days=grace_days + 1),
            grace_period_days=grace_days,
        )

        self.assertEqual(filtered_uuids(in_grace=True), {last_day.uuid})
        self.assertEqual(filtered_uuids(in_grace=False), {just_past.uuid})

    @freeze_time(TODAY.isoformat())
    def test_project_not_yet_ended_is_not_in_grace(self):
        # The grace period only starts once end_date has passed, so a project
        # ending today or later is not in grace however long its grace period.
        self._project("today", end_date=TODAY, grace_period_days=30)
        self._project(
            "future", end_date=TODAY + datetime.timedelta(days=5), grace_period_days=30
        )
        self._project("no_end_date", end_date=None, grace_period_days=30)

        self.assertEqual(filtered_uuids(in_grace=True), set())

    @freeze_time(TODAY.isoformat())
    def test_matches_the_model_property(self):
        """The database-resolved filter must agree with is_in_grace_period."""
        grace_days = 30
        for offset in (0, 1, grace_days - 1, grace_days, grace_days + 1):
            self._project(
                f"ended_{offset}_days_ago",
                end_date=TODAY - datetime.timedelta(days=offset),
                grace_period_days=grace_days,
            )

        in_grace = filtered_uuids(in_grace=True)
        expected = {p.uuid for p in Project.objects.all() if p.is_in_grace_period}
        self.assertEqual(in_grace, expected)
