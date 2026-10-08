"""The regular project usage update, sent as openportal.project_usage_update.

Covers the award pace port (which has to agree with HomePort's award pace
card), who is sent the update, and what it says.
"""

import datetime
from unittest import mock

from constance.test import override_config
from django.core import mail
from django.test import TestCase

from waldur_core.core.models import Notification
from waldur_core.structure.tests import factories as structure_factories
from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_mastermind.invoices import models as invoice_models
from waldur_openportal import award_pace, models, project_updates, tasks

DEST = "airr.brics.isambard-ai"
KEY = "openportal.project_usage_update"
TODAY = datetime.date(2026, 7, 1)
# The run's "now". Passed in rather than frozen: freezegun's FakeDate is cached
# by the openportal extension the first time it parses a date, and then breaks
# every later test in the same process that hands it a real one.
NOON = datetime.datetime(2026, 7, 1, 12, tzinfo=datetime.UTC)


def _at(year, month, day, hour=12):
    return datetime.datetime(year, month, day, hour, tzinfo=datetime.UTC)


def _d(year, month, day):
    return datetime.date(year, month, day)


def _pace(used, today=TODAY, start=_d(2026, 1, 1), end=_d(2026, 12, 31)):
    return award_pace.build_award_pace(start, end, 53750, used, today)


class AwardPaceTest(TestCase):
    """The same cases as HomePort's awardPace.test.ts."""

    def test_the_window_is_measured_in_calendar_days(self):
        pace = _pace(0)
        self.assertEqual(
            (pace.total_days, pace.elapsed_days, pace.remaining_days), (364, 181, 183)
        )

    def test_the_rate_needed_is_from_today_not_the_whole_window(self):
        pace = _pace(10000)
        self.assertAlmostEqual(pace.required_per_day, (53750 - 10000) / 183)
        self.assertAlmostEqual(pace.required_per_day_overall, 53750 / 364)

    def test_there_is_no_rate_to_aim_at_on_the_last_day(self):
        self.assertIsNone(_pace(10000, end=TODAY).required_per_day)

    def test_half_the_window_and_half_the_allocation_is_on_track(self):
        pace = _pace(26875)
        self.assertEqual(pace.status, award_pace.PaceStatus.ON_TRACK)
        self.assertLess(abs(pace.projected_difference), 500)

    def test_falling_off_the_line_is_behind_and_loses_allocation(self):
        pace = _pace(10000)
        self.assertEqual(pace.status, award_pace.PaceStatus.BEHIND)
        self.assertAlmostEqual(pace.projected_loss, 53750 - 10000 / 181 * 364)
        self.assertIsNone(pace.exhaustion_date)

    def test_running_in_front_is_ahead_and_runs_out_early(self):
        pace = _pace(40000)
        self.assertEqual(pace.status, award_pace.PaceStatus.AHEAD)
        self.assertLess(pace.exhaustion_date, pace.end_date)
        self.assertEqual(pace.projected_loss, 0)

    def test_a_used_up_allocation_is_exhausted_not_ahead(self):
        pace = _pace(53750)
        self.assertEqual(pace.status, award_pace.PaceStatus.EXHAUSTED)
        self.assertIsNone(pace.exhaustion_date)

    def test_past_the_end_date_the_award_has_ended(self):
        pace = _pace(10000, today=_d(2027, 1, 5))
        self.assertEqual(pace.status, award_pace.PaceStatus.ENDED)
        self.assertEqual(pace.elapsed_days, pace.total_days)

    def test_the_verdict_waits_over_the_first_days(self):
        self.assertEqual(_pace(0, today=_d(2026, 1, 8)).status, "settling")
        self.assertEqual(_pace(0, today=_d(2026, 1, 20)).status, "behind")

    def test_a_short_award_settles_for_a_quarter_of_its_window_at_most(self):
        pace = _pace(0, today=_d(2026, 1, 6), end=_d(2026, 1, 21))
        self.assertEqual(pace.status, award_pace.PaceStatus.BEHIND)

    def test_there_is_no_pace_without_a_window_or_an_allocation(self):
        self.assertIsNone(award_pace.build_award_pace(None, TODAY, 100, 0, TODAY))
        self.assertIsNone(award_pace.build_award_pace(TODAY, None, 100, 0, TODAY))
        self.assertIsNone(award_pace.build_award_pace(TODAY, TODAY, 100, 0, TODAY))
        self.assertIsNone(
            award_pace.build_award_pace(_d(2026, 1, 1), TODAY, 0, 0, TODAY)
        )

    def test_the_window_falls_back_to_attachment_and_the_project_end(self):
        self.assertEqual(
            award_pace.resolve_award_window(None, None, _d(2026, 2, 1), TODAY),
            (_d(2026, 2, 1), TODAY),
        )
        self.assertEqual(
            award_pace.resolve_award_window(_d(2026, 1, 1), _d(2026, 9, 1), None, None),
            (_d(2026, 1, 1), _d(2026, 9, 1)),
        )

    def test_an_allocation_string_splits_into_number_and_unit(self):
        self.assertEqual(award_pace.split_allocation("15000 GPUHR"), (15000.0, "GPUHR"))
        self.assertEqual(award_pace.split_allocation("junk"), (0.0, ""))
        self.assertEqual(award_pace.split_allocation(None), (0.0, ""))


class ProjectUpdateTestMixin:
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        self.project.end_date = _d(2026, 12, 31)
        self.project.grace_period_days = 30
        self.project.save()
        self.member = self.fixture.admin
        self.notification = Notification.objects.create(key=KEY, enabled=True)
        # Usage per award, by RemoteProject pk. Award usage itself is covered by
        # test_remote_project_usage; here it is only an input.
        self.usage = {}

    def award(self, used=10000, allocation="53750 GPUHR", **kwargs):
        defaults = {
            "destination": DEST,
            "identifier": "u6ac.brics",
            "current_project": self.project,
            "state": models.RemoteProjectState.ACTIVE,
            "last_sent_details": {
                "allocation": allocation,
                "start_date": "2026-01-01",
                "end_date": "2026-12-31",
            },
        }
        defaults.update(kwargs)
        remote_project = models.RemoteProject.objects.create(**defaults)
        self.usage[remote_project.pk] = used
        return remote_project

    def local_allocation(self, usage=12.5, credit=100):
        models.Allocation.objects.create(
            name="local",
            project=self.project,
            service_settings=structure_factories.ServiceSettingsFactory(
                customer=self.fixture.customer
            ),
            node_usage=usage,
        )
        if credit is not None:
            invoice_models.CustomerCredit.objects.create(
                customer=self.fixture.customer, value=1000
            )
            invoice_models.ProjectCredit.objects.create(
                project=self.project, value=credit
            )

    def send(self, now=NOON):
        with mock.patch.object(
            project_updates.utils,
            "get_remote_project_total_hours",
            side_effect=lambda rp: self.usage.get(rp.pk, 0),
        ):
            return project_updates.send_project_updates(now)

    def context(self):
        with mock.patch.object(
            project_updates.utils,
            "get_remote_project_total_hours",
            side_effect=lambda rp: self.usage.get(rp.pk, 0),
        ):
            return project_updates.build_context(self.project, 14, TODAY)


class WhoIsSentAnUpdateTest(ProjectUpdateTestMixin, TestCase):
    def test_a_project_holding_an_award_is_sent_one(self):
        self.award()
        self.assertEqual(self.send(), 1)
        self.assertEqual(mail.outbox[0].to, [self.member.email])

    def test_a_remotely_managed_project_is_not(self):
        """Its awarding portal sends the update; members must not get two."""
        self.local_allocation()
        models.ManagedProject.objects.create(
            destination="awards.brics",
            identifier="u6ac.brics",
            local_identifier="u6ac.isambard",
            project=self.project,
        )
        self.assertEqual(self.send(), 0)
        self.assertEqual(len(mail.outbox), 0)

    def test_a_project_with_local_allocations_and_a_credit_is_sent_one(self):
        self.local_allocation()
        self.assertEqual(self.send(), 1)

    def test_local_allocations_without_a_credit_are_not_reported(self):
        self.local_allocation(credit=None)
        self.assertEqual(self.send(), 0)

    def test_an_errored_or_deleted_award_is_not_reported(self):
        self.award(state=models.RemoteProjectState.ERROR)
        self.award(state=models.RemoteProjectState.DELETED, destination="other.brics")
        self.assertEqual(self.send(), 0)

    def test_a_pending_or_stale_award_still_is(self):
        self.award(state=models.RemoteProjectState.STALE)
        self.assertEqual(self.send(), 1)

    def test_nothing_is_sent_while_the_notification_is_disabled(self):
        self.award()
        self.notification.enabled = False
        self.notification.save()
        self.assertEqual(self.send(), 0)
        self.assertFalse(
            models.ProjectNotification.objects.filter(
                project=self.project, last_notification__isnull=False
            ).exists()
        )

    def test_an_expired_project_is_not_sent_one(self):
        self.award()
        self.project.end_date = _d(2026, 5, 1)
        self.project.grace_period_days = 0
        self.project.save()
        self.assertEqual(self.send(), 0)

    def test_it_is_sent_once_per_period(self):
        self.award()
        self.assertEqual(self.send(), 1)
        self.assertEqual(self.send(_at(2026, 7, 14)), 0)
        self.assertEqual(self.send(_at(2026, 7, 15)), 1)

    def test_a_frequency_of_zero_turns_it_off(self):
        self.award()
        models.ProjectNotification.objects.create(project=self.project, frequency=0)
        self.assertEqual(self.send(), 0)

    def test_nothing_goes_out_outside_office_hours(self):
        self.award()
        self.assertEqual(self.send(_at(2026, 7, 1, hour=20)), 0)
        self.assertEqual(self.send(_at(2026, 7, 1, hour=9)), 0)

    def test_the_task_sends_them(self):
        with mock.patch.object(project_updates, "send_project_updates") as send:
            tasks.send_notifications()
        send.assert_called_once_with()


class WhatTheUpdateSaysTest(ProjectUpdateTestMixin, TestCase):
    def body(self, now=NOON):
        self.assertEqual(self.send(now), 1)
        message = mail.outbox[0]
        return message.body, message.alternatives[0][0]

    def test_behind_says_how_much_will_be_lost(self):
        self.award(used=10000)
        award = self.context()["awards"][0]
        self.assertEqual(award["status"], "behind")
        self.assertEqual(award["projected_loss"], "33,639.5 GPUHR")
        self.assertEqual(award["projected_loss_percent"], 63)

        text, html = self.body()
        self.assertIn("You are BEHIND", text)
        self.assertIn("projected to lose 33,639.5 GPUHR (63% of your allocation)", text)
        self.assertIn("33,639.5 GPUHR (63% of your allocation)", html)

    def test_ahead_says_when_it_runs_out(self):
        self.award(used=40000)
        text, _ = self.body()
        self.assertIn("You are AHEAD", text)
        self.assertIn("will run out on", text)
        self.assertNotIn("projected to lose", text)

    def test_the_figures_match_the_pace_card(self):
        self.award(used=10000)
        award = self.context()["awards"][0]
        self.assertEqual(award["used"], "10,000 GPUHR")
        self.assertEqual(award["allocation"], "53,750 GPUHR")
        self.assertEqual(award["used_percent"], 19)
        self.assertEqual(award["expected_percent"], 50)

    def test_the_grace_period_and_deletion_date_are_given(self):
        self.award()
        context = self.context()
        self.assertEqual(context["deletion_date"], _d(2027, 1, 30))
        self.assertEqual(context["data_last_access_date"], _d(2027, 1, 29))
        self.assertEqual(context["grace_change_deadline"], _d(2027, 1, 20))

        text, _ = self.body()
        self.assertIn("grace period of 30 days", text)
        self.assertIn("your last day to access your data will be 29 January 2027", text)
        self.assertIn("You will lose access on 30 January 2027", text)
        self.assertIn("contact the allocator of your project", text)
        self.assertIn("Please request any change no later than 20 January 2027", text)
        self.assertIn("the earlier you ask, the more likely", text)

    def test_without_a_grace_period_data_goes_at_the_end_date(self):
        self.project.grace_period_days = 0
        self.project.save()
        self.award()
        text, _ = self.body()
        self.assertIn("There is no grace period", text)
        self.assertIn("copy back your data by the end of 30 December 2026", text)
        self.assertIn("You will lose access on 31 December 2026", text)

    def test_in_the_grace_period_it_says_so(self):
        self.award()
        text, _ = self.body(_at(2027, 1, 22))
        self.assertIn("is now in its grace period", text)
        self.assertIn("your last day to access your data is 29 January 2027", text)
        self.assertIn("(20 January 2027) has now passed", text)
        self.assertIn("unlikely unless there are exceptional circumstances", text)

    def test_each_award_is_reported_busiest_first(self):
        self.award(used=10000)
        self.award(used=900, allocation="1000 NHR", destination="other.brics.somewhere")
        names = [award["allocation"] for award in self.context()["awards"]]
        self.assertEqual(names, ["1,000 NHR", "53,750 GPUHR"])

    def test_local_usage_is_this_month_against_the_credit(self):
        self.local_allocation(usage=12.5, credit=100)
        context = self.context()
        self.assertEqual(
            context["local_usage"],
            {"usage_this_month": "12.5", "credit_remaining": "87.5"},
        )
        text, _ = self.body()
        self.assertIn("This month, 12.5 node hours have been used", text)

    def test_it_points_to_the_documentation_when_there_is_some(self):
        self.award()
        with override_config(DOCS_URL="https://docs.example.org/"):
            text, html = self.body()
        self.assertIn(
            "For more information, read the documentation at https://docs.example.org/",
            text,
        )
        self.assertIn('href="https://docs.example.org/"', html)

    def test_it_links_to_the_project(self):
        self.award()
        self.assertIn(self.project.uuid.hex, self.context()["project_url"])


class EndDatesAreExclusiveTest(ProjectUpdateTestMixin, TestCase):
    """Access ends at the start of the end date, so the email names the day
    before it wherever it tells someone how long they have - as HomePort does.
    People read "ends on the 31st" as "I have until the 31st"."""

    def body(self, now=NOON):
        self.assertEqual(self.send(now), 1)
        return mail.outbox[-1].body

    def test_the_countdown_runs_to_the_last_day_of_access(self):
        self.award()
        context = self.context()
        self.assertEqual(context["last_access_date"], _d(2026, 12, 30))
        self.assertEqual(context["days_until_last_access"], 182)
        text = self.body()
        self.assertIn(
            "The last day of access to your project is 30 December 2026, "
            "which is in 182 days",
            text,
        )
        self.assertIn("Access ends at the start of 31 December 2026", text)

    def test_the_day_before_the_end_date_is_the_last_day(self):
        self.award()
        self.assertIn("30 December 2026, which is today", self.body(_at(2026, 12, 30)))

    def test_on_the_end_date_itself_the_project_has_ended(self):
        self.award()
        text = self.body(_at(2026, 12, 31))
        self.assertIn("is now in its grace period", text)
        self.assertNotIn("The last day of access to your project", text)

    def test_the_pace_names_the_last_day_of_the_award(self):
        self.award(used=10000)
        self.assertEqual(
            self.context()["awards"][0]["last_access_date"], _d(2026, 12, 30)
        )
        text = self.body()
        self.assertIn("by the end of 30 December 2026, the last day of the award", text)
        self.assertNotIn("31 December 2026, the last day", text)


class GracePeriodEmailsTest(ProjectUpdateTestMixin, TestCase):
    """The end date is 31 December 2026 and the grace period 30 days, so the
    data's last day is 29 January, it is deleted on 30 January, and the last
    day to ask for an extension is 20 January - 10 days before deletion."""

    def setUp(self):
        super().setUp()
        for event in ("grace_period_started", "grace_period_ending"):
            Notification.objects.create(key=f"openportal.{event}", enabled=True)
        self.award()

    def sent(self, now):
        before = len(mail.outbox)
        self.send(now)
        return mail.outbox[before:]

    def grace(self, days):
        self.project.grace_period_days = days
        self.project.save()

    def last_sent(self, day):
        models.ProjectNotification.objects.update_or_create(
            project=self.project, defaults={"last_notification": day}
        )

    def test_on_the_end_date_members_are_told_to_copy_back_now(self):
        [message] = self.sent(_at(2026, 12, 31))
        self.assertIn("has ended - copy back your data now", message.subject)
        self.assertIn("Its last day of access was 30 December 2026", message.body)
        self.assertIn("You MUST start copying back your data NOW", message.body)
        self.assertIn("last day to access your data is 29 January 2027", message.body)
        self.assertIn(
            "allocator of your project no later than 20 January", message.body
        )
        self.assertIn("the earlier you ask, the more likely", message.body)

    def test_it_is_sent_once(self):
        self.assertEqual(len(self.sent(_at(2026, 12, 31))), 1)
        self.assertEqual(len(self.sent(_at(2026, 12, 31, hour=14))), 0)

    def test_it_takes_the_place_of_an_update_due_the_same_day(self):
        [message] = self.sent(_at(2026, 12, 31))
        self.assertIn("has ended", message.subject)
        # and the update's period restarts from it
        self.assertEqual(len(self.sent(_at(2027, 1, 1))), 0)

    def test_ten_days_before_deletion_members_are_told_to_contact_the_allocator(self):
        self.last_sent(_d(2027, 1, 10))
        [message] = self.sent(_at(2027, 1, 20))
        self.assertIn("will be deleted in 10 days", message.subject)
        self.assertIn("is in its grace period", message.body)
        self.assertIn("deletion in 10 days, on 30 January 2027", message.body)
        self.assertIn("contact the allocator of your project TODAY", message.body)
        self.assertIn(
            "After today, an extension is unlikely unless there are exceptional "
            "circumstances",
            message.body,
        )
        self.assertEqual(len(self.sent(_at(2027, 1, 20, hour=15))), 0)

    def test_nothing_is_sent_on_other_days_in_the_grace_period(self):
        self.last_sent(_d(2027, 1, 10))
        self.assertEqual(len(self.sent(_at(2027, 1, 19))), 0)
        self.assertEqual(len(self.sent(_at(2027, 1, 21))), 0)

    def test_they_go_whatever_the_update_frequency(self):
        models.ProjectNotification.objects.create(project=self.project, frequency=0)
        self.assertEqual(len(self.sent(_at(2026, 12, 15))), 0)
        self.assertEqual(len(self.sent(_at(2026, 12, 31))), 1)
        self.assertEqual(len(self.sent(_at(2027, 1, 20))), 1)

    def test_a_disabled_grace_email_leaves_the_update_to_go_out(self):
        Notification.objects.filter(key="openportal.grace_period_started").update(
            enabled=False
        )
        [message] = self.sent(_at(2026, 12, 31))
        self.assertIn("project update", message.subject)

    def test_a_ten_day_grace_period_gets_one_email_on_the_end_date(self):
        self.grace(10)
        [message] = self.sent(_at(2026, 12, 31))
        self.assertIn("has ended", message.subject)
        self.assertIn("contact the allocator of your project TODAY", message.body)
        self.assertEqual(len(self.sent(_at(2026, 12, 31, hour=15))), 0)

    def test_a_short_grace_period_is_warned_before_the_end_date(self):
        self.grace(5)
        [ending] = self.sent(_at(2026, 12, 26))
        self.assertIn("will be deleted in 10 days", ending.subject)
        self.assertIn("The last day of access to your Waldur project", ending.body)
        self.assertIn("followed by a grace period of 5 days", ending.body)

        [started] = self.sent(_at(2026, 12, 31))
        self.assertIn("that date has now passed", started.body)
        self.assertIn(
            "unlikely unless there are exceptional circumstances", started.body
        )
        self.assertIn(
            "contact the allocator of your project as soon as possible", started.body
        )
        self.assertNotIn("cannot be extended", started.body)

    def test_without_a_grace_period_only_the_ten_day_warning_goes(self):
        self.grace(0)
        [ending] = self.sent(_at(2026, 12, 21))
        self.assertIn("deletion in 10 days, on 31 December 2026", ending.body)
        self.assertNotIn("grace period of", ending.body)
        self.assertEqual(len(self.sent(_at(2026, 12, 31))), 0)
