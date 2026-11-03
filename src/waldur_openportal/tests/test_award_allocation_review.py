import datetime
import decimal
import json
from unittest import mock

import openportal
from django.test import TestCase

from waldur_core.core.enums import ReviewStates
from waldur_core.structure.tests import factories as structure_factories
from waldur_openportal import exceptions, models, tasks
from waldur_openportal.board import OpenPortalBoard

from .test_award_membership import DESTINATION, IDENTIFIER, MembershipSyncFixture

D = decimal.Decimal
TODAY = datetime.date.today()
# Allocations above this many credits need approval by the project class.
APPROVAL_LIMIT = 100


def award(allocation=None, **fields):
    payload = dict(fields)
    if allocation is not None:
        payload["allocation"] = allocation
    for key, value in list(payload.items()):
        if isinstance(value, datetime.date):
            payload[key] = value.isoformat()
    return openportal.AwardDetails(json.dumps(payload))


class AllocationReviewTest(MembershipSyncFixture, TestCase):
    """
    Only an allocation increase of at least one credit over the credits last
    approved waits for review; every other change to a live award applies.
    """

    def setUp(self):
        super().setUp()
        self.project_template.convert_to_credits.side_effect = (
            lambda allocation: allocation.size
        )
        self.project_template.action_is_rejected.return_value = False
        self.project_template.action_needs_approval.side_effect = (
            lambda allocation=None: (allocation or 0) > APPROVAL_LIMIT
        )
        self.managed_project.approved_credits = D("1000.0")
        self.managed_project.pending_allocation = None
        self.utils.get_project_credits.return_value = D("1000.0")

    def update(self, details, force_approve=False):
        return self.board.update_award(
            openportal.ProjectIdentifier(IDENTIFIER),
            details,
            force_approve=force_approve,
        )

    def assert_not_held(self):
        self.managed_project.set_needs_approval.assert_not_called()

    def test_rounding_difference_is_not_a_change(self):
        self.utils.get_project_credits.return_value = D("999.9634")

        self.update(award("1000.0 credits"))

        self.utils.set_project_credits.assert_not_called()
        self.assert_not_held()

    def test_increase_under_one_credit_is_applied_without_review(self):
        self.update(award("1000.5 credits"))

        self.utils.set_project_credits.assert_called_once_with(
            self.project, D("1000.5")
        )
        self.assert_not_held()
        # Not approved by anyone, so the baseline stays where it was.
        self.assertEqual(self.managed_project.approved_credits, D("1000.0"))

    def test_small_increases_cannot_add_up_unreviewed(self):
        self.utils.get_project_credits.return_value = D("1000.8")

        with self.assertRaises(exceptions.ManagedProjectPendingError):
            self.update(award("1001.5 credits"))

        self.utils.set_project_credits.assert_not_called()
        self.assertEqual(self.managed_project.pending_allocation, D("1001.5"))

    def test_increase_waits_but_everything_else_is_applied(self):
        new_end = TODAY + datetime.timedelta(days=90)
        details = award(
            "1500 credits",
            name="Renamed",
            end_date=new_end,
            start_date=TODAY,
            membership_control="locked",
            members={"alice@example.com": "admin"},
        )

        with self.assertRaises(exceptions.ManagedProjectPendingError):
            self.update(details)

        self.utils.set_project_credits.assert_not_called()
        self.assertEqual(self.managed_project.pending_allocation, D("1500.0"))
        self.managed_project.set_needs_approval.assert_called_once()
        self.assertEqual(self.project.name, "Renamed")
        self.assertEqual(self.project.end_date, new_end)
        self.assertEqual(self.project.start_date, TODAY)
        self.utils.remove_project_member.assert_called_once_with(
            self.project, "bob@example.com"
        )

    def test_extension_applies_while_increase_is_pending(self):
        self.managed_project.is_approved.return_value = False
        self.managed_project.is_pending.return_value = True
        self.managed_project.pending_allocation = D("1500.0")
        new_end = TODAY + datetime.timedelta(days=30)

        with self.assertRaises(exceptions.ManagedProjectPendingError):
            self.update(award("1500 credits", end_date=new_end))

        self.assertEqual(self.project.end_date, new_end)
        self.utils.set_project_credits.assert_not_called()

    def test_withdrawn_increase_releases_the_award(self):
        self.managed_project.is_approved.return_value = False
        self.managed_project.is_pending.return_value = True
        self.managed_project.pending_allocation = D("1500.0")

        self.update(award("1000 credits"))

        self.assertIsNone(self.managed_project.pending_allocation)
        self.managed_project.set_needs_approval.assert_called_once_with(False)

    def test_approved_increase_is_applied_and_becomes_the_baseline(self):
        self.managed_project.pending_allocation = D("1500.0")

        self.update(award("1500 credits"), force_approve=True)

        self.utils.set_project_credits.assert_called_once_with(
            self.project, D("1500.0")
        )
        self.assertEqual(self.managed_project.approved_credits, D("1500.0"))
        self.assertIsNone(self.managed_project.pending_allocation)
        self.assert_not_held()

    def test_increase_within_approval_limit_is_approved_by_policy(self):
        self.managed_project.approved_credits = D("10")
        self.utils.get_project_credits.return_value = D("10")

        self.update(award("50 credits"))

        self.utils.set_project_credits.assert_called_once_with(self.project, D("50"))
        self.assertEqual(self.managed_project.approved_credits, D("50"))
        self.assert_not_held()

    def test_decrease_is_applied(self):
        self.update(award("800 credits"))

        self.utils.set_project_credits.assert_called_once_with(self.project, D("800"))
        self.assert_not_held()

    def test_baseline_starts_from_current_credits(self):
        self.managed_project.approved_credits = None
        self.utils.get_project_credits.return_value = D("1000.04")

        self.update(award("1000.0 credits"))

        self.assertEqual(self.managed_project.approved_credits, D("1000.0"))

    def test_award_waiting_to_attach_is_not_live(self):
        """
        Pending with a project but no pending increase (e.g. waiting to be
        attached to an existing project): nothing is applied.
        """
        self.managed_project.is_approved.return_value = False
        self.managed_project.is_pending.return_value = True

        with self.assertRaises(exceptions.ManagedProjectPendingError):
            self.update(award("1000 credits", name="Renamed"))

        self.project.save.assert_not_called()


class AwardEndDateOnArrivalTest(TestCase):
    def setUp(self):
        patcher = mock.patch(
            "waldur_openportal.config.ensure_config_loaded", return_value=True
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.board = OpenPortalBoard(DESTINATION)
        self.identifier = openportal.ProjectIdentifier(IDENTIFIER)

    def test_new_award_ending_today_is_refused(self):
        with self.assertRaises(exceptions.ManagedProjectRejectedError):
            self.board.create_award(
                self.identifier, award("10 credits", end_date=TODAY, name="x")
            )

        self.assertFalse(models.ManagedProject.objects.exists())

    def test_ended_award_is_not_recreated(self):
        with mock.patch.object(OpenPortalBoard, "create_award") as create_award:
            with self.assertRaises(exceptions.ManagedProjectRejectedError):
                self.board.update_award(
                    self.identifier,
                    award("10 credits", end_date=TODAY - datetime.timedelta(days=1)),
                )

        create_award.assert_not_called()


class RejectEndedWaitingAwardsTest(TestCase):
    def setUp(self):
        self.robot = structure_factories.UserFactory()
        patcher = mock.patch(
            "waldur_openportal.tasks.utils.get_openportal_robot",
            return_value=self.robot,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def make(self, identifier, end_date, state=ReviewStates.PENDING, project=None):
        return models.ManagedProject.objects.create(
            destination=DESTINATION,
            identifier=identifier,
            details={"name": identifier, "end_date": end_date.isoformat()},
            state=state,
            project=project,
        )

    def test_rejects_only_ended_awards_without_a_project(self):
        ended = self.make("ended.someportal", TODAY)
        draft = self.make(
            "draft.someportal", TODAY - datetime.timedelta(days=3), ReviewStates.DRAFT
        )
        running = self.make("running.someportal", TODAY + datetime.timedelta(days=1))
        attached = self.make(
            "attached.someportal",
            TODAY - datetime.timedelta(days=3),
            project=structure_factories.ProjectFactory(),
        )

        with mock.patch.object(models.ManagedProject, "notify_rejected") as notify:
            tasks.reject_ended_waiting_awards()

        for managed_project, state in (
            (ended, ReviewStates.REJECTED),
            (draft, ReviewStates.REJECTED),
            (running, ReviewStates.PENDING),
            (attached, ReviewStates.PENDING),
        ):
            managed_project.refresh_from_db()
            self.assertEqual(managed_project.state, state, managed_project.identifier)

        self.assertEqual(notify.call_count, 2)
        self.assertEqual(ended.reviewed_by, self.robot)
        self.assertTrue(
            models.ManagedProjectAuditEntry.objects.filter(
                identifier=ended.identifier,
                event_type=models.ManagedProjectAuditEventType.REJECTED,
            ).exists()
        )


class AuditNoteRepeatTest(TestCase):
    def setUp(self):
        self.managed_project = models.ManagedProject.objects.create(
            destination=DESTINATION, identifier=IDENTIFIER, details={}
        )

    def record(self, note, event_type=None, **kwargs):
        return models.ManagedProjectAuditEntry.record(
            self.managed_project,
            event_type or models.ManagedProjectAuditEventType.DETAILS_UPDATED,
            note=note,
            **kwargs,
        )

    def notes(self):
        return list(
            models.ManagedProjectAuditEntry.objects.order_by(
                "timestamp", "id"
            ).values_list("note", flat=True)
        )

    def test_repeated_note_is_recorded_once(self):
        self.record("not applied: grace period")
        self.assertIsNone(self.record("not applied: grace period"))

        self.assertEqual(self.notes(), ["not applied: grace period"])

    def test_note_repeated_after_another_entry_is_recorded(self):
        self.record("not applied: grace period")
        self.record("something else")
        self.record("not applied: grace period")

        self.assertEqual(len(self.notes()), 3)

    def test_same_note_as_a_different_event_is_recorded(self):
        self.record("x")
        self.record("x", event_type=models.ManagedProjectAuditEventType.NOTE_ADDED)

        self.assertEqual(len(self.notes()), 2)

    def test_same_note_by_another_user_is_recorded(self):
        self.record("x", event_type=models.ManagedProjectAuditEventType.NOTE_ADDED)
        self.record(
            "x",
            event_type=models.ManagedProjectAuditEventType.NOTE_ADDED,
            performed_by=structure_factories.UserFactory(),
        )

        self.assertEqual(len(self.notes()), 2)
