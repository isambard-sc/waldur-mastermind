import datetime
from unittest import mock

from constance.test import override_config
from django.test import TestCase
from django.utils import timezone

from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models, tasks, utils
from waldur_mastermind.proposal.enums import CallStates, ProposalStates
from waldur_mastermind.proposal.tests import factories


def days_ago(days):
    return timezone.now() - datetime.timedelta(days=days)


class DraftsAtCutoffTest(TestCase):
    def setUp(self):
        self.call = factories.CallFactory(
            state=CallStates.ACTIVE, carry_over_drafts=False
        )
        self.round = factories.RoundFactory(
            call=self.call, start_time=days_ago(10), cutoff_time=days_ago(1)
        )
        self.draft = factories.ProposalFactory(
            round=self.round, state=ProposalStates.DRAFT
        )

    def sweep(self):
        with mock.patch.object(
            tasks.notify_proposal_creator_about_cancelled_proposal, "apply_async"
        ):
            tasks.proposals_for_ended_rounds_should_be_cancelled()
        self.draft.refresh_from_db()

    def test_upstream_default_cancels(self):
        self.sweep()
        self.assertEqual(self.draft.state, ProposalStates.CANCELED)

    def test_call_can_keep_its_drafts(self):
        self.call.cancel_drafts_at_cutoff = False
        self.call.save()
        self.sweep()
        self.assertEqual(self.draft.state, ProposalStates.DRAFT)
        self.assertEqual(utils.process_closed_round(self.round), [])
        self.draft.refresh_from_db()
        self.assertEqual(self.draft.state, ProposalStates.DRAFT)


@override_config(
    PROPOSAL_STALE_DRAFT_REMINDER_DAYS=14, PROPOSAL_STALE_DRAFT_DELETION_DAYS=14
)
class StaleDraftTest(TestCase):
    def setUp(self):
        self.call = factories.CallFactory(state=CallStates.ACTIVE)
        self.round = factories.RoundFactory(
            call=self.call, start_time=days_ago(60), cutoff_time=days_ago(-30)
        )
        self.owner = structure_factories.UserFactory()
        self.draft = factories.ProposalFactory(
            round=self.round, state=ProposalStates.DRAFT, created_by=self.owner
        )
        self.draft.add_user(self.owner, ProposalRole.MANAGER)
        self.set_modified(days_ago(15))

    def set_modified(self, when):
        models.Proposal.objects.filter(pk=self.draft.pk).update(modified=when)

    def remind(self):
        with mock.patch("waldur_core.core.utils.broadcast_mail") as mail:
            tasks.send_stale_proposal_reminders()
        self.draft.refresh_from_db()
        return mail

    def delete(self):
        with mock.patch("waldur_core.core.utils.broadcast_mail") as mail:
            tasks.delete_stale_proposals()
        return mail

    def test_warned_once_then_deleted(self):
        mail = self.remind()
        self.assertIsNotNone(self.draft.stale_reminder_sent_at)
        app, event, context, emails = mail.call_args.args
        self.assertEqual(event, "stale_proposal_reminder")
        self.assertEqual(context["days_until_deletion"], 14)
        self.assertEqual(emails, [self.owner.email])
        self.assertFalse(self.remind().called)

        # Not yet: the deletion waits 14 days from the warning.
        self.assertFalse(self.delete().called)
        self.assertTrue(models.Proposal.objects.filter(pk=self.draft.pk).exists())

        models.Proposal.objects.filter(pk=self.draft.pk).update(
            stale_reminder_sent_at=days_ago(15), modified=days_ago(30)
        )
        mail = self.delete()
        self.assertFalse(models.Proposal.objects.filter(pk=self.draft.pk).exists())
        self.assertEqual(mail.call_args.args[1], "stale_proposal_deleted")

    def test_change_after_warning_cancels_it(self):
        self.remind()
        models.Proposal.objects.filter(pk=self.draft.pk).update(
            stale_reminder_sent_at=days_ago(15), modified=days_ago(2)
        )
        self.assertFalse(self.delete().called)
        self.assertTrue(models.Proposal.objects.filter(pk=self.draft.pk).exists())
        # The next reminder run clears the warning.
        self.remind()
        self.assertIsNone(self.draft.stale_reminder_sent_at)

    def test_recent_drafts_and_other_states_left_alone(self):
        self.set_modified(days_ago(3))
        self.assertFalse(self.remind().called)
        self.set_modified(days_ago(30))
        models.Proposal.objects.filter(pk=self.draft.pk).update(
            state=ProposalStates.SUBMITTED
        )
        self.assertFalse(self.remind().called)

    def test_returned_proposals_are_the_call_managers(self):
        models.ProposalReturn.objects.create(
            proposal=self.draft,
            reason="Fix it",
            resubmit_by=timezone.now() + datetime.timedelta(days=30),
            previous_state=ProposalStates.SUBMITTED,
        )
        self.set_modified(days_ago(30))
        self.assertFalse(self.remind().called)
        self.assertIsNone(self.draft.stale_reminder_sent_at)

    @override_config(PROPOSAL_STALE_DRAFT_REMINDER_DAYS=0)
    def test_off_by_setting(self):
        self.assertFalse(self.remind().called)
        models.Proposal.objects.filter(pk=self.draft.pk).update(
            stale_reminder_sent_at=days_ago(60)
        )
        self.delete()
        self.assertTrue(models.Proposal.objects.filter(pk=self.draft.pk).exists())

    def test_editing_resources_or_documents_counts_as_a_change(self):
        offering = factories.RequestedOfferingFactory(call=self.call)
        factories.RequestedResourceFactory(
            proposal=self.draft, requested_offering=offering
        )
        self.draft.refresh_from_db()
        self.assertGreater(self.draft.modified, days_ago(1))
