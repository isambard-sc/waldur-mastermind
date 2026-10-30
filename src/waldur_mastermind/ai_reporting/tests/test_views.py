from unittest import mock

from constance.test.unittest import override_config as override_constance_config
from django.urls import reverse
from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession


class FeatureEnabledSwitchTest(test.APITestCase):
    """AI_REPORTING_ENABLED (ConstanceCheckExtensionMixin, same mechanism the
    chat app's AI_ASSISTANT_ENABLED uses) must gate the whole viewset, not
    just ask - list/retrieve included, matching chat's own MessageViewSet
    convention of treating the feature as entirely unavailable when off."""

    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.ask_url = reverse("ai-reporting-message-ask")
        self.list_url = reverse("ai-reporting-message-list")

    @override_constance_config(AI_REPORTING_ENABLED=False)
    def test_ask_is_rejected_while_disabled(self):
        response = self.client.post(self.ask_url, {"prompt": "How many projects?"})
        self.assertEqual(response.status_code, status.HTTP_424_FAILED_DEPENDENCY)

    @override_constance_config(AI_REPORTING_ENABLED=False)
    def test_list_is_rejected_while_disabled(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_424_FAILED_DEPENDENCY)

    def test_ask_works_normally_once_enabled_again(self):
        # Default is True - no override needed, just confirming the baseline
        # the two tests above are deviating from.
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            response = self.client.post(self.ask_url, {"prompt": "How many projects?"})
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)


class AskUsageLimitTest(test.APITestCase):
    """Confirms limits.enforce_usage_limits is actually wired into the ask
    action (see ai_reporting.tests.test_limits for the limit logic itself) -
    rejected before anything is created, not just logged after the fact."""

    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.ask_url = reverse("ai-reporting-message-ask")

    @override_constance_config(AI_REPORTING_TOKEN_LIMIT_DAILY=10)
    def test_ask_is_rejected_once_the_daily_limit_is_reached(self):
        session = ReportingSession.objects.create(user=self.staff)
        ReportingMessage.objects.create(
            session=session, prompt="earlier", status=ReportingMessage.Status.DONE,
            input_tokens=6, output_tokens=5,  # 11 >= 10
        )

        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay") as mock_delay:
            response = self.client.post(self.ask_url, {"prompt": "How many projects?"})

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        mock_delay.assert_not_called()
        self.assertFalse(
            ReportingMessage.objects.filter(prompt="How many projects?").exists(),
            "a rejected request must not create a message at all",
        )


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


class UsageStatsTest(test.APITestCase):
    """usage_stats is deliberately the one action in this viewset that is
    NOT scoped to the caller's own messages - these tests specifically
    confirm it sees every user's usage, unlike list/retrieve."""

    def setUp(self):
        self.staff = structure_factories.UserFactory(
            is_staff=True, username="staffer", first_name="Stacy", last_name="Staff"
        )
        self.other_user = structure_factories.UserFactory(
            username="other", first_name="Olly", last_name="Other"
        )
        self.client.force_authenticate(user=self.staff)
        self.url = reverse("ai-reporting-message-usage-stats")

    def _message(self, user, input_tokens, output_tokens):
        session = ReportingSession.objects.create(user=user)
        return ReportingMessage.objects.create(
            session=session, prompt="x", status=ReportingMessage.Status.DONE,
            input_tokens=input_tokens, output_tokens=output_tokens,
        )

    def test_regular_user_is_denied(self):
        regular = structure_factories.UserFactory()
        self.client.force_authenticate(user=regular)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_totals_include_every_users_usage_not_just_the_callers(self):
        self._message(self.staff, input_tokens=100, output_tokens=50)
        self._message(self.other_user, input_tokens=200, output_tokens=75)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_input_tokens"], 300)
        self.assertEqual(response.data["total_output_tokens"], 125)
        self.assertEqual(response.data["total_requests"], 2)

    def test_by_user_breaks_usage_down_per_person(self):
        self._message(self.staff, input_tokens=100, output_tokens=50)
        self._message(self.other_user, input_tokens=200, output_tokens=75)

        response = self.client.get(self.url)

        by_user = {row["username"]: row for row in response.data["by_user"]}
        self.assertEqual(by_user["staffer"]["input_tokens"], 100)
        self.assertEqual(by_user["staffer"]["full_name"], "Stacy Staff")
        self.assertEqual(by_user["other"]["input_tokens"], 200)

    def test_daily_groups_by_calendar_date(self):
        import datetime

        from django.utils import timezone

        today_message = self._message(self.staff, input_tokens=10, output_tokens=5)
        yesterday_message = self._message(self.staff, input_tokens=20, output_tokens=10)
        ReportingMessage.objects.filter(pk=yesterday_message.pk).update(
            created=timezone.now() - datetime.timedelta(days=1)
        )

        response = self.client.get(self.url, {"days": 7})

        self.assertEqual(len(response.data["daily"]), 2)
        self.assertEqual(response.data["period_days"], 7)
        # response.data holds raw Python objects (DATE_FORMAT is None
        # project-wide - see base_settings.py - so DateField passes the
        # native date through unconverted here; actual JSON responses handle
        # serialization separately), so compare against a date object too.
        today_date = today_message.created.date()
        by_date = {row["date"]: row for row in response.data["daily"]}
        self.assertEqual(by_date[today_date]["input_tokens"], 10)

    def test_days_outside_the_window_are_excluded(self):
        import datetime

        from django.utils import timezone

        old_message = self._message(self.staff, input_tokens=999, output_tokens=999)
        ReportingMessage.objects.filter(pk=old_message.pk).update(
            created=timezone.now() - datetime.timedelta(days=40)
        )

        response = self.client.get(self.url, {"days": 30})

        self.assertEqual(response.data["total_input_tokens"], 0)
        self.assertEqual(response.data["total_requests"], 0)

    def test_days_parameter_is_bounded(self):
        response = self.client.get(self.url, {"days": 99999})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["period_days"], 365)

        response = self.client.get(self.url, {"days": "not-a-number"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["period_days"], 30)

    def test_empty_period_returns_zeros_not_an_error(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["total_input_tokens"], 0)
        self.assertEqual(response.data["total_output_tokens"], 0)
        self.assertEqual(response.data["total_requests"], 0)
        self.assertEqual(response.data["daily"], [])
        self.assertEqual(response.data["by_user"], [])
