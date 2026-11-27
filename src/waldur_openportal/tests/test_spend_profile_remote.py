"""Spend profiles on the awarding side: checked, recorded and sent to the site
in AwardDetails; and what each site says it supports."""

import datetime
import json
import unittest
from unittest import mock

from django.test import TestCase
from django.utils import timezone
from rest_framework import status, test

from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CustomerRole, ProjectRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_openportal import (
    exceptions,
    models,
    remote_project_service,
    spend_profiles,
    tasks,
)
from waldur_openportal.client import OpenPortalClient

# Spend profiles need openportal 0.94; until Waldur pins it, an environment
# with an older release cannot set or carry one, and these tests cannot run.
needs_spend_profiles = unittest.skipUnless(
    spend_profiles.is_supported(), "needs openportal 0.94 (spend profiles)"
)

TODAY = datetime.date(2027, 5, 15)
BEFORE_AWARD = datetime.date(2026, 12, 1)
DESTINATION = "airr.brics.isambard-ai"
AWARD = {
    "allocation": "1000 NHR",
    "start_date": "2027-01-01",
    "end_date": "2027-12-31",
}
PROFILE = [
    {"from": "2027-01-01", "minimum": "250 NHR", "maximum": "250 NHR"},
    {"from": "2027-04-01", "minimum": "250 NHR", "maximum": "250 NHR"},
    {"from": "2027-07-01", "maximum": "500 NHR"},
]


@needs_spend_profiles
class ProfileRulesTest(TestCase):
    def test_entries_are_sorted_and_spelt_as_award_details_does(self):
        self.assertEqual(
            spend_profiles.normalise(list(reversed(PROFILE))),
            PROFILE,
        )

    def test_duplicate_dates_are_refused(self):
        with self.assertRaisesMessage(spend_profiles.SpendProfileError, "2027-01-01"):
            spend_profiles.parse([PROFILE[0], {"from": "2027-01-01"}])

    def test_maximum_below_minimum_is_refused(self):
        with self.assertRaises(spend_profiles.SpendProfileError):
            spend_profiles.parse(
                [{"from": "2027-01-01", "minimum": "300 NHR", "maximum": "100 NHR"}]
            )

    def test_periods_run_until_the_next_entry(self):
        periods = spend_profiles.periods(PROFILE, datetime.date(2027, 12, 31))
        self.assertEqual(
            [(p["from"], p["to"]) for p in periods],
            [
                (datetime.date(2027, 1, 1), datetime.date(2027, 3, 31)),
                (datetime.date(2027, 4, 1), datetime.date(2027, 6, 30)),
                (datetime.date(2027, 7, 1), datetime.date(2027, 12, 31)),
            ],
        )

    # TODAY is 2027-05-15: January-March has ended, April-June is current,
    # July onwards is upcoming.

    def test_the_current_periods_controls_may_change_or_clear(self):
        changed = [PROFILE[0], {"from": "2027-04-01", "minimum": "100 NHR"}, PROFILE[2]]
        spend_profiles.validate_change(PROFILE, changed, TODAY)
        cleared = [PROFILE[0], {"from": "2027-04-01"}, PROFILE[2]]
        spend_profiles.validate_change(PROFILE, cleared, TODAY)

    def test_when_the_current_period_ends_may_move_to_today_or_later(self):
        for start in ("2027-05-15", "2027-05-16", "2027-09-01"):
            moved = [*PROFILE[:2], {"from": start, "maximum": "500 NHR"}]
            spend_profiles.validate_change(PROFILE, moved, TODAY)
        with self.assertRaisesMessage(spend_profiles.SpendProfileError, "past"):
            spend_profiles.validate_change(
                PROFILE, [*PROFILE[:2], {"from": "2027-05-14"}], TODAY
            )

    def test_an_ended_period_keeps_its_controls(self):
        changed = [{"from": "2027-01-01", "minimum": "100 NHR"}, *PROFILE[1:]]
        with self.assertRaisesMessage(spend_profiles.SpendProfileError, "has ended"):
            spend_profiles.validate_change(PROFILE, changed, TODAY)
        with self.assertRaisesMessage(spend_profiles.SpendProfileError, "has ended"):
            spend_profiles.validate_change(PROFILE, PROFILE[1:], TODAY)

    def test_an_ended_period_keeps_its_end(self):
        """Leaving out, or moving, the current period after an ended one would
        move the ended one's last day."""
        for changed in (
            [PROFILE[0], PROFILE[2]],
            [PROFILE[0], {"from": "2027-05-20", "maximum": "250 NHR"}, PROFILE[2]],
        ):
            with self.assertRaisesMessage(
                spend_profiles.SpendProfileError, "must still start on 2027-04-01"
            ):
                spend_profiles.validate_change(PROFILE, changed, TODAY)

    def test_the_current_period_may_go_when_nothing_has_ended(self):
        profile = PROFILE[1:]
        spend_profiles.validate_change(profile, [PROFILE[2]], TODAY)
        spend_profiles.validate_change(profile, [], TODAY)

    def test_the_profile_cannot_be_removed_once_a_period_has_ended(self):
        with self.assertRaisesMessage(spend_profiles.SpendProfileError, "has ended"):
            spend_profiles.validate_change(PROFILE, [], TODAY)

    def test_a_new_period_cannot_start_in_the_past(self):
        added = [*PROFILE, {"from": "2027-05-01"}]
        with self.assertRaisesMessage(spend_profiles.SpendProfileError, "past"):
            spend_profiles.validate_change(PROFILE, added, TODAY)
        spend_profiles.validate_change(
            PROFILE, [*PROFILE, {"from": "2027-05-15"}], TODAY
        )

    def test_future_periods_may_change_or_go(self):
        spend_profiles.validate_change(PROFILE, PROFILE[:2], TODAY)
        spend_profiles.validate_change(
            PROFILE, [*PROFILE[:2], {"from": "2027-08-01", "maximum": "100 NHR"}], TODAY
        )

    def test_once_the_award_has_ended_its_last_period_has_too(self):
        after = datetime.date(2028, 1, 2)
        end = datetime.date(2027, 12, 31)
        spend_profiles.validate_change(PROFILE, PROFILE, after, end)
        changed = [*PROFILE[:2], {"from": "2027-07-01", "maximum": "900 NHR"}]
        with self.assertRaisesMessage(spend_profiles.SpendProfileError, "has ended"):
            spend_profiles.validate_change(PROFILE, changed, after, end)


class RemoteProjectFixture:
    def setUp(self):
        self.project = structure_factories.ProjectFactory()
        allocation = models.RemoteAllocation.objects.create(
            name="award",
            project=self.project,
            service_settings=structure_factories.ServiceSettingsFactory(
                customer=self.project.customer
            ),
            backend_id="airr-gw_1.airr",
            remote_project_identifier="u6aa.brics",
        )
        self.remote_project = models.RemoteProject.objects.create(
            destination=DESTINATION,
            identifier="u6aa.brics",
            state=models.RemoteProjectState.ACTIVE,
            current_project=self.project,
            remote_allocation=allocation,
            last_sent_details=AWARD,
        )


@needs_spend_profiles
@mock.patch("waldur_openportal.views.timezone.now")
class SetSpendProfileApiTest(RemoteProjectFixture, test.APITransactionTestCase):
    def setUp(self):
        super().setUp()
        self.staff = structure_factories.UserFactory(is_staff=True)
        patcher = mock.patch.object(tasks.update_remote_project, "delay")
        self.update = patcher.start()
        self.addCleanup(patcher.stop)

    def url(self, action="set-spend-profile"):
        return (
            f"/api/openportal-remote-projects/{self.remote_project.uuid.hex}/{action}/"
        )

    def post(self, user, profile):
        self.client.force_authenticate(user)
        return self.client.post(self.url(), {"spend_profile": profile}, format="json")

    def at(self, now_mock, day=BEFORE_AWARD):
        now_mock.return_value = timezone.make_aware(
            datetime.datetime.combine(day, datetime.time(12))
        )

    def test_staff_set_a_profile_and_it_is_sent(self, now):
        self.at(now)
        response = self.post(self.staff, list(reversed(PROFILE)))
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["spend_profile"], PROFILE)
        self.remote_project.refresh_from_db()
        self.assertEqual(self.remote_project.spend_profile, PROFILE)
        self.update.assert_called_once()
        audit = models.RemoteProjectAuditEntry.objects.get(
            remote_project=self.remote_project
        )
        self.assertEqual(audit.new_details, {"spend_profile": PROFILE})
        self.assertIn("spend exactly 250 NHR", audit.note)

    def test_organisation_owner_may_set_it(self, now):
        self.at(now)
        CustomerRole.OWNER.add_permission(PermissionEnum.LIST_PROJECTS)
        owner = structure_factories.UserFactory()
        self.project.customer.add_user(owner, CustomerRole.OWNER)
        response = self.post(owner, PROFILE)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

    def test_a_project_member_may_not(self, now):
        self.at(now)
        ProjectRole.MEMBER.add_permission(PermissionEnum.LIST_PROJECTS)
        member = structure_factories.UserFactory()
        self.project.add_user(member, ProjectRole.MEMBER)
        response = self.post(member, PROFILE)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.remote_project.refresh_from_db()
        self.assertIsNone(self.remote_project.spend_profile)

    def test_amounts_must_be_in_the_awards_units(self, now):
        self.at(now)
        response = self.post(
            self.staff, [{"from": "2027-06-01", "maximum": "10 GPUHR"}]
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("NHR", str(response.data))

    def test_dates_must_fall_within_the_award(self, now):
        self.at(now)
        response = self.post(self.staff, [{"from": "2028-01-01", "maximum": "10 NHR"}])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("after the award ends", str(response.data))

    def test_the_past_cannot_be_rewritten(self, now):
        self.at(now)
        self.assertEqual(self.post(self.staff, PROFILE).status_code, 200)
        self.at(now, TODAY)
        changed = [{"from": "2027-01-01", "minimum": "100 NHR"}, *PROFILE[1:]]
        response = self.post(self.staff, changed)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("has ended", str(response.data))

    def test_the_current_periods_controls_may_change(self, now):
        self.at(now)
        self.assertEqual(self.post(self.staff, PROFILE).status_code, 200)
        self.at(now, TODAY)
        changed = [PROFILE[0], {"from": "2027-04-01"}, PROFILE[2]]
        response = self.post(self.staff, changed)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.remote_project.refresh_from_db()
        self.assertEqual(self.remote_project.spend_profile, changed)

    def test_the_profile_stays_once_a_period_has_ended(self, now):
        self.at(now)
        self.assertEqual(self.post(self.staff, PROFILE).status_code, 200)
        self.at(now, TODAY)
        response = self.post(self.staff, [])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("cannot be removed", str(response.data))

    def test_the_same_profile_again_changes_nothing(self, now):
        self.at(now)
        self.post(self.staff, PROFILE)
        self.update.reset_mock()
        self.assertEqual(self.post(self.staff, PROFILE).status_code, 200)
        self.update.assert_not_called()
        self.assertEqual(
            models.RemoteProjectAuditEntry.objects.filter(
                remote_project=self.remote_project
            ).count(),
            1,
        )

    def test_on_a_running_award_periods_start_today_or_later(self, now):
        self.at(now, TODAY)
        response = self.post(self.staff, [{"from": "2027-05-15", "maximum": "300 NHR"}])
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        response = self.post(self.staff, [{"from": "2027-05-14", "maximum": "300 NHR"}])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


@needs_spend_profiles
class AwardDetailsCarryTheProfileTest(RemoteProjectFixture, TestCase):
    def sent(self):
        return json.loads(self.remote_project.award_details().to_json())

    def test_no_profile_is_not_sent(self):
        self.assertNotIn("spend_profile", self.sent())

    def test_a_profile_is_sent(self):
        self.remote_project.spend_profile = PROFILE
        self.assertEqual(self.sent()["spend_profile"], PROFILE)

    def test_an_empty_profile_is_sent_as_empty(self):
        self.remote_project.spend_profile = []
        self.assertEqual(self.sent()["spend_profile"], [])


class SiteFeaturesTest(RemoteProjectFixture, TestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch(
            "waldur_openportal.config.ensure_config_loaded", return_value=True
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_unconfigured_portal_does_not_know(self):
        with mock.patch(
            "waldur_openportal.config.ensure_config_loaded", return_value=False
        ):
            self.assertIsNone(
                remote_project_service.refresh_site_features(self.remote_project)
            )
        self.remote_project.refresh_from_db()
        self.assertIsNone(self.remote_project.site_features)

    def test_the_answer_is_kept(self):
        with mock.patch.object(
            OpenPortalClient, "run", return_value=["award_spend_maximums"]
        ):
            features = remote_project_service.refresh_site_features(self.remote_project)
        self.assertEqual(features, ["award_spend_maximums"])
        self.remote_project.refresh_from_db()
        self.assertEqual(self.remote_project.site_features, ["award_spend_maximums"])
        self.assertIsNotNone(self.remote_project.site_features_checked_at)

    def test_a_site_that_refuses_the_question_supports_nothing(self):
        with mock.patch.object(
            OpenPortalClient,
            "run",
            side_effect=exceptions.OpenPortalError("unknown instruction"),
        ):
            remote_project_service.refresh_site_features(self.remote_project)
        self.remote_project.refresh_from_db()
        self.assertEqual(self.remote_project.site_features, [])

    def test_a_timeout_says_nothing(self):
        self.remote_project.site_features = ["award_spend_maximums"]
        self.remote_project.save()
        with mock.patch.object(
            OpenPortalClient,
            "run",
            side_effect=exceptions.OpenPortalTimeoutError("timed out"),
        ):
            self.assertIsNone(
                remote_project_service.refresh_site_features(self.remote_project)
            )
        self.remote_project.refresh_from_db()
        self.assertEqual(self.remote_project.site_features, ["award_spend_maximums"])

    def test_the_daily_task_asks_each_site_once(self):
        models.RemoteProject.objects.create(
            destination=DESTINATION,
            identifier="u6ab.brics",
            state=models.RemoteProjectState.ACTIVE,
            current_project=structure_factories.ProjectFactory(),
        )
        with mock.patch.object(
            OpenPortalClient, "run", return_value=["award_spend_minimums"]
        ) as run:
            tasks.refresh_site_features()
        run.assert_called_once()
        for remote_project in models.RemoteProject.objects.all():
            self.assertEqual(remote_project.site_features, ["award_spend_minimums"])
