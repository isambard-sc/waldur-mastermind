import datetime

from django.utils import timezone
from rest_framework import status, test

from waldur_core.logging import event_logger
from waldur_core.logging.enums import EventType
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CallRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import models
from waldur_mastermind.proposal.enums import CallStates, ProposalStates
from waldur_mastermind.proposal.tests import factories


class ReviewerVisibilityTest(test.APITestCase):
    def setUp(self):
        for role in (CallRole.REVIEWER, CallRole.PANEL_MEMBER, CallRole.MANAGER):
            role.add_permission(PermissionEnum.LIST_PROPOSALS)
        self.call = factories.CallFactory(state=CallStates.ACTIVE)
        self.round = factories.RoundFactory(
            call=self.call,
            start_time=timezone.now() - datetime.timedelta(days=5),
            cutoff_time=timezone.now() + datetime.timedelta(days=5),
        )
        self.draft = factories.ProposalFactory(
            round=self.round, state=ProposalStates.DRAFT
        )
        self.submitted = factories.ProposalFactory(
            round=self.round, state=ProposalStates.SUBMITTED
        )
        self.reviewed = factories.ProposalFactory(
            round=self.round, state=ProposalStates.IN_REVIEW
        )

        self.reviewer = structure_factories.UserFactory()
        self.call.add_user(self.reviewer, CallRole.REVIEWER)
        factories.ReviewFactory(
            proposal=self.reviewed,
            reviewer=self.reviewer,
            state=models.Review.States.IN_REVIEW,
        )
        self.panel_member = structure_factories.UserFactory()
        self.call.add_user(self.panel_member, CallRole.PANEL_MEMBER)
        self.manager = structure_factories.UserFactory()
        self.call.add_user(self.manager, CallRole.MANAGER)

    def visible(self, user):
        self.client.force_authenticate(user)
        response = self.client.get(
            "/api/proposal-proposals/", {"call_uuid": self.call.uuid.hex}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return {row["uuid"] for row in response.data}

    def uuids(self, *proposals):
        return {p.uuid.hex for p in proposals}

    def test_evaluators_never_see_drafts(self):
        self.assertEqual(
            self.visible(self.reviewer), self.uuids(self.submitted, self.reviewed)
        )
        self.assertEqual(
            self.visible(self.panel_member), self.uuids(self.submitted, self.reviewed)
        )

    def test_call_manager_sees_everything(self):
        self.assertEqual(
            self.visible(self.manager),
            self.uuids(self.draft, self.submitted, self.reviewed),
        )

    def test_call_can_limit_reviewers_to_their_reviews(self):
        self.call.reviewers_see_assigned_only = True
        self.call.save()
        self.assertEqual(self.visible(self.reviewer), self.uuids(self.reviewed))
        # Panels discuss the whole call.
        self.assertEqual(
            self.visible(self.panel_member), self.uuids(self.submitted, self.reviewed)
        )

    def test_manager_who_also_reviews_still_sees_everything(self):
        self.call.add_user(self.reviewer, CallRole.MANAGER)
        self.call.reviewers_see_assigned_only = True
        self.call.save()
        self.assertEqual(
            self.visible(self.reviewer),
            self.uuids(self.draft, self.submitted, self.reviewed),
        )

    def test_no_review_of_a_draft(self):
        staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(staff)
        response = self.client.post(
            "/api/proposal-reviews/",
            {
                "proposal": factories.ProposalFactory.get_url(self.draft),
                "reviewer": structure_factories.UserFactory.get_url(self.reviewer),
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_only_those_running_the_call_read_its_event_feed(self):
        event_logger.emit(
            "Something happened on {call_name}.",
            event_type=EventType.PROPOSAL_RETURNED,
            event_context={"call_name": self.call.name},
            scopes=[self.call],
        )
        scope = factories.CallFactory.get_protected_url(self.call)
        for user, sees in (
            (self.manager, True),
            (self.reviewer, False),
            (self.panel_member, False),
        ):
            self.client.force_authenticate(user)
            response = self.client.get("/api/events/", {"scope": scope})
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # The feed also carries the role grants made in setUp.
            self.assertEqual(bool(response.data), sees, user)
