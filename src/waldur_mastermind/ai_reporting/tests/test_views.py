from unittest import mock

from django.urls import reverse
from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession


class AskPermissionTest(test.APITestCase):
    def setUp(self):
        self.ask_url = reverse("ai-reporting-message-ask")

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_staff_can_ask(self, mock_delay):
        staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=staff)

        response = self.client.post(self.ask_url, {"prompt": "How many projects?"})

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        mock_delay.assert_called_once()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_support_can_ask(self, mock_delay):
        support = structure_factories.UserFactory(is_support=True)
        self.client.force_authenticate(user=support)

        response = self.client.post(self.ask_url, {"prompt": "How many projects?"})

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        mock_delay.assert_called_once()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_regular_user_is_denied(self, mock_delay):
        user = structure_factories.UserFactory()
        self.client.force_authenticate(user=user)

        response = self.client.post(self.ask_url, {"prompt": "How many projects?"})

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        mock_delay.assert_not_called()

    def test_unauthenticated_is_rejected(self):
        response = self.client.post(self.ask_url, {"prompt": "How many projects?"})
        self.assertIn(
            response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)
        )


class AskActionTest(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.ask_url = reverse("ai-reporting-message-ask")

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_creates_pending_message_and_enqueues_task(self, mock_delay):
        response = self.client.post(self.ask_url, {"prompt": "How many projects?"})

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data["status"], ReportingMessage.Status.PENDING)
        message = ReportingMessage.objects.get(uuid=response.data["uuid"])
        self.assertEqual(message.prompt, "How many projects?")
        mock_delay.assert_called_once_with(message.pk)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_reuses_the_same_session_across_calls(self, mock_delay):
        self.client.post(self.ask_url, {"prompt": "first"})
        self.client.post(self.ask_url, {"prompt": "second"})

        self.assertEqual(ReportingSession.objects.filter(user=self.staff).count(), 1)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_rejects_empty_prompt(self, mock_delay):
        response = self.client.post(self.ask_url, {"prompt": ""})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_delay.assert_not_called()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_second_ask_while_first_pending_does_not_enqueue_a_duplicate(
        self, mock_delay
    ):
        first = self.client.post(self.ask_url, {"prompt": "first"})
        second = self.client.post(self.ask_url, {"prompt": "second, while first is pending"})

        self.assertEqual(mock_delay.call_count, 1)
        self.assertEqual(first.data["uuid"], second.data["uuid"])

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_new_session_bypasses_the_pending_reuse_check(self, mock_delay):
        self.client.post(self.ask_url, {"prompt": "first"})
        response = self.client.post(
            self.ask_url, {"prompt": "second", "new_session": True}
        )

        self.assertEqual(mock_delay.call_count, 2)
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_new_session_actually_creates_a_second_session_row(self, mock_delay):
        """The whole point of many-per-user: new_session must mint a distinct
        ReportingSession, not just reset something inside the existing one -
        otherwise two browser tabs could never get independent, concurrently
        runnable conversations."""
        self.client.post(self.ask_url, {"prompt": "first"})
        self.client.post(self.ask_url, {"prompt": "second", "new_session": True})

        self.assertEqual(ReportingSession.objects.filter(user=self.staff).count(), 2)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_can_target_a_specific_existing_session(self, mock_delay):
        first_response = self.client.post(self.ask_url, {"prompt": "first"})
        self.client.post(self.ask_url, {"prompt": "second", "new_session": True})
        first_session = first_response.data["session"]

        response = self.client.post(
            self.ask_url, {"prompt": "back to the first one", "session": first_session}
        )

        self.assertEqual(response.data["session"], first_session)
        self.assertEqual(ReportingSession.objects.filter(user=self.staff).count(), 2)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_cannot_target_another_users_session(self, mock_delay):
        other_user = structure_factories.UserFactory(is_staff=True)
        other_session = ReportingSession.objects.create(user=other_user)

        response = self.client.post(
            self.ask_url, {"prompt": "hi", "session": other_session.uuid}
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        mock_delay.assert_not_called()


class ReportingMessageViewSetTest(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.other_staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)

        self.session = ReportingSession.objects.create(user=self.staff)
        self.other_session = ReportingSession.objects.create(user=self.other_staff)

        self.list_url = reverse("ai-reporting-message-list")

    def test_list_returns_only_the_callers_own_messages(self):
        mine = ReportingMessage.objects.create(session=self.session, prompt="mine")
        ReportingMessage.objects.create(session=self.other_session, prompt="not mine")

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        uuids = {item["uuid"] for item in response.data}
        self.assertEqual(uuids, {str(mine.uuid)})

    def test_create_update_destroy_are_disabled(self):
        message = ReportingMessage.objects.create(session=self.session, prompt="x")
        detail_url = reverse(
            "ai-reporting-message-detail", kwargs={"uuid": message.uuid}
        )

        self.assertEqual(
            self.client.post(self.list_url, {"prompt": "direct create"}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.patch(detail_url, {"answer": "fabricated"}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.delete(detail_url).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
