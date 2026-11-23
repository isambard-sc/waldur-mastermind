import base64
import datetime
from unittest import mock

from constance.test.unittest import override_config as override_constance_config
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.urls import reverse
from django.utils import timezone
from rest_framework import status, test

from waldur_core.core.models import PersonalAccessToken
from waldur_core.media import access as media_access
from waldur_core.media import models as media_models
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingFile,
    ReportingMessage,
    ReportingSession,
    ReportingUsageRecord,
)


@override_constance_config(AI_REPORTING_ENABLED=True)
class FeatureEnabledSwitchTest(test.APITestCase):
    """AI_REPORTING_ENABLED gates every action, not just ask."""

    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.ask_url = reverse("ai-reporting-message-ask")
        self.list_url = reverse("ai-reporting-message-list")

    @override_constance_config(AI_REPORTING_ENABLED=False)
    def test_ask_is_rejected_while_disabled(self):
        response = self.client.post(
            self.ask_url, {"prompt": "How many projects?", "new_session": True}
        )
        self.assertEqual(response.status_code, status.HTTP_424_FAILED_DEPENDENCY)

    @override_constance_config(AI_REPORTING_ENABLED=False)
    def test_list_is_rejected_while_disabled(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_424_FAILED_DEPENDENCY)

    def test_ask_works_normally_once_enabled_again(self):
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            response = self.client.post(
                self.ask_url, {"prompt": "How many projects?", "new_session": True}
            )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)


@override_constance_config(AI_REPORTING_ENABLED=True)
class AskUsageLimitTest(test.APITestCase):
    """ask rejects over-limit requests before creating anything. The limit
    logic itself is tested in test_limits."""

    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.ask_url = reverse("ai-reporting-message-ask")

    @override_constance_config(AI_REPORTING_TOKEN_LIMIT_DAILY=10)
    def test_ask_is_rejected_once_the_daily_limit_is_reached(self):
        # The limit reads usage records, not messages.
        ReportingUsageRecord.objects.create(
            user=self.staff,
            status=ReportingUsageRecord.Status.DONE,
            input_tokens=6,
            output_tokens=5,  # 11 >= 10
        )

        with mock.patch(
            "waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"
        ) as mock_delay:
            response = self.client.post(
                self.ask_url, {"prompt": "How many projects?", "new_session": True}
            )

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        mock_delay.assert_not_called()
        self.assertFalse(
            ReportingMessage.objects.filter(prompt="How many projects?").exists(),
            "a rejected request must not create a message at all",
        )


@override_constance_config(AI_REPORTING_ENABLED=True)
class AskPermissionTest(test.APITestCase):
    def setUp(self):
        self.ask_url = reverse("ai-reporting-message-ask")

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_staff_can_ask(self, mock_delay):
        staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=staff)

        response = self.client.post(
            self.ask_url, {"prompt": "How many projects?", "new_session": True}
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        mock_delay.assert_called_once()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_support_can_ask(self, mock_delay):
        support = structure_factories.UserFactory(is_support=True)
        self.client.force_authenticate(user=support)

        response = self.client.post(
            self.ask_url, {"prompt": "How many projects?", "new_session": True}
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        mock_delay.assert_called_once()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_regular_user_is_denied(self, mock_delay):
        user = structure_factories.UserFactory()
        self.client.force_authenticate(user=user)

        response = self.client.post(
            self.ask_url, {"prompt": "How many projects?", "new_session": True}
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        mock_delay.assert_not_called()

    def test_unauthenticated_is_rejected(self):
        response = self.client.post(
            self.ask_url, {"prompt": "How many projects?", "new_session": True}
        )
        self.assertIn(
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )


@override_constance_config(AI_REPORTING_ENABLED=True)
class AskActionTest(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.ask_url = reverse("ai-reporting-message-ask")

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_creates_pending_message_and_enqueues_task(self, mock_delay):
        response = self.client.post(
            self.ask_url, {"prompt": "How many projects?", "new_session": True}
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data["status"], ReportingMessage.Status.PENDING)
        message = ReportingMessage.objects.get(uuid=response.data["uuid"])
        self.assertEqual(message.prompt, "How many projects?")
        mock_delay.assert_called_once_with(message.pk)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_task_is_queued_only_after_the_message_is_committed(self, mock_delay):
        # conftest runs on_commit callbacks at once, so capture it instead.
        with mock.patch(
            "waldur_mastermind.ai_reporting.views.transaction.on_commit"
        ) as on_commit:
            self.client.post(
                self.ask_url, {"prompt": "How many projects?", "new_session": True}
            )
        mock_delay.assert_not_called()

        on_commit.call_args.args[0]()
        mock_delay.assert_called_once()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_continues_the_session_it_is_given(self, mock_delay):
        first = self.client.post(self.ask_url, {"prompt": "first", "new_session": True})
        ReportingMessage.objects.update(status=ReportingMessage.Status.DONE)
        self.client.post(
            self.ask_url, {"prompt": "second", "session": first.data["session"]}
        )

        self.assertEqual(ReportingSession.objects.filter(user=self.staff).count(), 1)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_needs_a_session_or_new_session(self, mock_delay):
        neither = self.client.post(self.ask_url, {"prompt": "hi"})
        session = ReportingSession.objects.create(user=self.staff)
        both = self.client.post(
            self.ask_url,
            {"prompt": "hi", "session": session.uuid.hex, "new_session": True},
        )

        self.assertEqual(neither.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(both.status_code, status.HTTP_400_BAD_REQUEST)
        mock_delay.assert_not_called()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_rejects_empty_prompt(self, mock_delay):
        response = self.client.post(self.ask_url, {"prompt": "", "new_session": True})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mock_delay.assert_not_called()

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_a_follow_up_waits_for_the_answer_in_its_conversation(self, mock_delay):
        first = self.client.post(self.ask_url, {"prompt": "first", "new_session": True})
        second = self.client.post(
            self.ask_url,
            {
                "prompt": "second, while first is pending",
                "session": first.data["session"],
            },
        )

        self.assertEqual(second.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(mock_delay.call_count, 1)
        self.assertEqual(ReportingMessage.objects.count(), 1)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_the_same_question_sent_twice_returns_the_pending_one(self, mock_delay):
        """A double click or a retry must not start a second run."""
        first = self.client.post(self.ask_url, {"prompt": "first", "new_session": True})
        second = self.client.post(
            self.ask_url, {"prompt": "first", "session": first.data["session"]}
        )

        self.assertEqual(second.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(first.data["uuid"], second.data["uuid"])
        self.assertEqual(mock_delay.call_count, 1)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_questions_in_different_conversations_run_side_by_side(self, mock_delay):
        self.client.post(self.ask_url, {"prompt": "first", "new_session": True})
        response = self.client.post(
            self.ask_url, {"prompt": "second", "new_session": True}
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(mock_delay.call_count, 2)
        self.assertEqual(ReportingSession.objects.filter(user=self.staff).count(), 2)

    @override_constance_config(AI_REPORTING_MAX_QUESTIONS_PER_USER=2)
    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_a_user_can_only_run_a_few_at_once(self, mock_delay):
        self.client.post(self.ask_url, {"prompt": "one", "new_session": True})
        self.client.post(self.ask_url, {"prompt": "two", "new_session": True})
        third = self.client.post(self.ask_url, {"prompt": "three", "new_session": True})

        self.assertEqual(third.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(
            third.data["detail"],
            "You already have 2 questions running. Wait for one to finish.",
        )
        self.assertEqual(ReportingSession.objects.filter(user=self.staff).count(), 2)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_new_session_actually_creates_a_second_session_row(self, mock_delay):
        self.client.post(self.ask_url, {"prompt": "first", "new_session": True})
        ReportingMessage.objects.update(status=ReportingMessage.Status.DONE)
        self.client.post(self.ask_url, {"prompt": "second", "new_session": True})

        self.assertEqual(ReportingSession.objects.filter(user=self.staff).count(), 2)

    @mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay")
    def test_ask_can_target_a_specific_existing_session(self, mock_delay):
        first_response = self.client.post(
            self.ask_url, {"prompt": "first", "new_session": True}
        )
        ReportingMessage.objects.update(status=ReportingMessage.Status.DONE)
        self.client.post(self.ask_url, {"prompt": "second", "new_session": True})
        ReportingMessage.objects.update(status=ReportingMessage.Status.DONE)
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

        foreign = self.client.post(
            self.ask_url, {"prompt": "hi", "session": other_session.uuid}
        )
        unknown = self.client.post(self.ask_url, {"prompt": "hi", "session": "0" * 32})

        # Same answer either way, so it doesn't reveal that the session exists.
        self.assertEqual(foreign.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(foreign.status_code, unknown.status_code)
        mock_delay.assert_not_called()


@override_constance_config(AI_REPORTING_ENABLED=True)
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

    def test_list_can_be_filtered_to_one_of_the_callers_own_sessions(self):
        other_own_session = ReportingSession.objects.create(user=self.staff)
        in_session = ReportingMessage.objects.create(
            session=self.session, prompt="in this session"
        )
        ReportingMessage.objects.create(
            session=other_own_session, prompt="a different one of my sessions"
        )

        response = self.client.get(self.list_url, {"session": str(self.session.uuid)})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        uuids = {item["uuid"] for item in response.data}
        self.assertEqual(uuids, {str(in_session.uuid)})

    def test_session_filter_cannot_reach_another_users_session(self):
        ReportingMessage.objects.create(session=self.other_session, prompt="not mine")

        response = self.client.get(
            self.list_url, {"session": str(self.other_session.uuid)}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

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


@override_constance_config(AI_REPORTING_ENABLED=True)
class UsageStatsTest(test.APITestCase):
    """usage_stats covers every user, not just the caller. It reads usage
    records, so these tests create those directly."""

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
        return ReportingUsageRecord.objects.create(
            user=user,
            status=ReportingUsageRecord.Status.DONE,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
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
        today_message = self._message(self.staff, input_tokens=10, output_tokens=5)
        yesterday_message = self._message(self.staff, input_tokens=20, output_tokens=10)
        ReportingUsageRecord.objects.filter(pk=yesterday_message.pk).update(
            created=timezone.now() - datetime.timedelta(days=1)
        )

        response = self.client.get(self.url, {"days": 7})

        self.assertEqual(len(response.data["daily"]), 2)
        self.assertEqual(response.data["period_days"], 7)
        # response.data holds a date object, not a string, since DATE_FORMAT is None.
        today_date = today_message.created.date()
        by_date = {row["date"]: row for row in response.data["daily"]}
        self.assertEqual(by_date[today_date]["input_tokens"], 10)

    def test_days_outside_the_window_are_excluded(self):
        old_message = self._message(self.staff, input_tokens=999, output_tokens=999)
        ReportingUsageRecord.objects.filter(pk=old_message.pk).update(
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

    def test_deleted_user_still_appears_in_the_breakdown(self):
        self._message(self.other_user, input_tokens=7, output_tokens=3)
        self.other_user.delete()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        row = response.data["by_user"][0]
        self.assertIsNone(row["user"])
        self.assertEqual(row["full_name"], "")
        self.assertEqual(row["input_tokens"], 7)

    def test_cache_tokens_are_totalled(self):
        ReportingUsageRecord.objects.create(
            user=self.staff,
            status=ReportingUsageRecord.Status.DONE,
            cache_read_tokens=4000,
            cache_write_tokens=300,
        )

        response = self.client.get(self.url)

        self.assertEqual(response.data["total_cache_read_tokens"], 4000)
        self.assertEqual(response.data["total_cache_write_tokens"], 300)

    def test_usage_survives_the_message_that_produced_it_being_deleted(self):
        # Usage must survive the message being deleted.
        session = ReportingSession.objects.create(user=self.staff)
        message = ReportingMessage.objects.create(
            session=session,
            prompt="x",
            status=ReportingMessage.Status.DONE,
            input_tokens=10,
            output_tokens=5,
        )
        ReportingUsageRecord.objects.create(
            user=self.staff,
            status=ReportingUsageRecord.Status.DONE,
            input_tokens=10,
            output_tokens=5,
        )

        message.delete()
        response = self.client.get(self.url)

        self.assertEqual(response.data["total_input_tokens"], 10)
        self.assertEqual(response.data["total_output_tokens"], 5)
        self.assertEqual(response.data["total_requests"], 1)


@override_constance_config(AI_REPORTING_ENABLED=True)
class EnabledRolesIntegrationTest(test.APITestCase):
    """check_enabled_roles is applied to the real endpoints, except
    usage_stats, which stays staff/support only."""

    def setUp(self):
        self.ask_url = reverse("ai-reporting-message-ask")
        self.usage_stats_url = reverse("ai-reporting-message-usage-stats")

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="disabled")
    def test_disabled_blocks_even_staff(self):
        staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=staff)
        response = self.client.post(self.ask_url, {"prompt": "hi", "new_session": True})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="all")
    def test_an_old_all_value_does_not_let_a_regular_user_ask(self):
        regular = structure_factories.UserFactory()
        self.client.force_authenticate(user=regular)
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            response = self.client.post(
                self.ask_url, {"prompt": "hi", "new_session": True}
            )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


@override_constance_config(AI_REPORTING_ENABLED=True)
class ReportingFileViewSetTest(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.other_staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)

        self.session = ReportingSession.objects.create(user=self.staff)
        self.message = ReportingMessage.objects.create(
            session=self.session, prompt="chart the projects", answer="Here it is."
        )
        self.file = ReportingFile.objects.create(
            message=self.message,
            name="chart.png",
            file=ContentFile(b"fake png bytes", name="chart.png"),
        )

        self.other_session = ReportingSession.objects.create(user=self.other_staff)
        self.other_message = ReportingMessage.objects.create(
            session=self.other_session, prompt="not mine"
        )
        self.other_file = ReportingFile.objects.create(
            message=self.other_message,
            name="not-mine.png",
            file=ContentFile(b"not mine either", name="not-mine.png"),
        )

        self.list_url = reverse("ai-reporting-file-list")

    def _detail_url(self, reporting_file):
        return reverse("ai-reporting-file-detail", kwargs={"uuid": reporting_file.uuid})

    def test_list_returns_only_the_callers_own_files_with_their_question(self):
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        uuids = {item["uuid"] for item in response.data}
        self.assertEqual(uuids, {str(self.file.uuid)})
        self.assertEqual(response.data[0]["prompt"], "chart the projects")
        self.assertEqual(str(response.data[0]["session"]), str(self.session.uuid))

    def test_list_includes_the_questions_title(self):
        ReportingMessage.objects.filter(pk=self.message.pk).update(
            title="Projects chart"
        )

        response = self.client.get(self.list_url)

        self.assertEqual(response.data[0]["title"], "Projects chart")

    def test_cannot_retrieve_another_users_file(self):
        response = self.client.get(self._detail_url(self.other_file))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_can_delete_own_file_and_its_bytes_are_freed(self):
        stored_file = self.file.file

        response = self.client.delete(self._detail_url(self.file))

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ReportingFile.objects.filter(pk=self.file.pk).exists())
        self.assertFalse(stored_file.storage.exists(stored_file.name))

    def test_cannot_delete_another_users_file(self):
        response = self.client.delete(self._detail_url(self.other_file))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(ReportingFile.objects.filter(pk=self.other_file.pk).exists())

    def test_create_and_update_are_disabled(self):
        self.assertEqual(
            self.client.post(self.list_url, {"name": "direct create"}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.patch(
                self._detail_url(self.file), {"name": "fabricated"}
            ).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    @override_constance_config(AI_REPORTING_ENABLED=False)
    def test_list_is_rejected_while_the_feature_is_disabled(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_424_FAILED_DEPENDENCY)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="disabled")
    def test_list_is_rejected_for_a_role_the_setting_excludes(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="staff_and_support")
    def test_a_support_user_can_list_and_delete_their_own_files(self):
        regular = structure_factories.UserFactory(is_support=True)
        regular_session = ReportingSession.objects.create(user=regular)
        regular_message = ReportingMessage.objects.create(
            session=regular_session, prompt="mine"
        )
        regular_file = ReportingFile.objects.create(
            message=regular_message,
            name="mine.png",
            file=ContentFile(b"mine", name="mine.png"),
        )
        self.client.force_authenticate(user=regular)

        list_response = self.client.get(self.list_url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            {item["uuid"] for item in list_response.data}, {str(regular_file.uuid)}
        )

        delete_response = self.client.delete(self._detail_url(regular_file))
        self.assertEqual(delete_response.status_code, status.HTTP_204_NO_CONTENT)


@override_constance_config(AI_REPORTING_ENABLED=True)
class ReportingSessionViewSetTest(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.other_staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)

        self.session = ReportingSession.objects.create(user=self.staff)
        self.first_message = ReportingMessage.objects.create(
            session=self.session, prompt="first question", answer="first answer"
        )
        self.second_message = ReportingMessage.objects.create(
            session=self.session, prompt="second question", answer="second answer"
        )

        # What's left once retention cleanup removes every message.
        self.empty_session = ReportingSession.objects.create(user=self.staff)

        self.other_session = ReportingSession.objects.create(user=self.other_staff)
        ReportingMessage.objects.create(session=self.other_session, prompt="not mine")

        self.list_url = reverse("ai-reporting-session-list")

    def _detail_url(self, session):
        return reverse("ai-reporting-session-detail", kwargs={"uuid": session.uuid})

    def test_list_returns_only_the_callers_own_non_empty_sessions(self):
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        uuids = {item["uuid"] for item in response.data}
        self.assertEqual(uuids, {str(self.session.uuid)})

    def test_first_prompt_and_message_count_are_reported(self):
        response = self.client.get(self.list_url)

        row = response.data[0]
        self.assertEqual(row["first_prompt"], "first question")
        self.assertEqual(row["message_count"], 2)

    def test_the_first_questions_title_labels_the_conversation(self):
        ReportingMessage.objects.filter(pk=self.first_message.pk).update(
            title="Active projects"
        )

        response = self.client.get(self.list_url)

        self.assertEqual(response.data[0]["title"], "Active projects")

    def test_ordered_most_recently_active_session_first(self):
        later_session = ReportingSession.objects.create(user=self.staff)
        ReportingMessage.objects.create(session=later_session, prompt="newer")

        response = self.client.get(self.list_url)

        uuids = [item["uuid"] for item in response.data]
        self.assertEqual(uuids[0], str(later_session.uuid))

    def test_cannot_retrieve_another_users_session(self):
        response = self.client.get(self._detail_url(self.other_session))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_create_update_destroy_are_disabled(self):
        self.assertEqual(
            self.client.post(self.list_url, {}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.patch(self._detail_url(self.session), {}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.delete(self._detail_url(self.session)).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    @override_constance_config(AI_REPORTING_ENABLED=False)
    def test_list_is_rejected_while_the_feature_is_disabled(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_424_FAILED_DEPENDENCY)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="disabled")
    def test_list_is_rejected_for_a_role_the_setting_excludes(self):
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


_FAKE_KEY = base64.b64encode(b"0" * 32).decode()


@override_constance_config(AI_REPORTING_ENABLED=True)
class HarnessConnectionApiTest(test.APITestCase):
    """Same read/write split as the Formbricks connection API."""

    url = "/api/ai-reporting-harness-connection/"

    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.support = structure_factories.UserFactory(is_support=True)
        self.regular = structure_factories.UserFactory()

    def test_staff_and_support_can_read_without_the_key(self):
        connection = HarnessConnection.get()
        connection.base_url = (
            "http://waldur-harness.waldur-harness.svc.cluster.local:8000"
        )
        connection.signing_private_key = _FAKE_KEY
        connection.save()

        for user in (self.staff, self.support):
            self.client.force_authenticate(user)
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertNotIn("signing_private_key", response.data)
            self.assertTrue(response.data["signing_private_key_set"])
            self.assertNotIn(_FAKE_KEY, response.content.decode())

    def test_a_regular_user_cannot_read_or_change_it(self):
        self.client.force_authenticate(self.regular)
        self.assertEqual(
            self.client.get(self.url).status_code, status.HTTP_403_FORBIDDEN
        )
        self.assertEqual(
            self.client.patch(self.url, {"base_url": "http://x:8000"}).status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_support_can_read_but_not_change_it(self):
        self.client.force_authenticate(self.support)
        response = self.client.patch(self.url, {"base_url": "http://x:8000"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_staff_can_change_the_url_and_leaving_out_the_key_keeps_it(self):
        HarnessConnection.get()  # creates the row with its default key: ""
        connection = HarnessConnection.get()
        connection.signing_private_key = _FAKE_KEY
        connection.save()

        self.client.force_authenticate(self.staff)
        response = self.client.patch(self.url, {"base_url": "http://x.ns.svc:8000"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        connection.refresh_from_db()
        self.assertEqual(connection.base_url, "http://x.ns.svc:8000")
        self.assertEqual(connection.signing_private_key, _FAKE_KEY)  # left out: kept

    def test_sending_an_empty_key_clears_it(self):
        connection = HarnessConnection.get()
        connection.signing_private_key = _FAKE_KEY
        connection.save()

        self.client.force_authenticate(self.staff)
        response = self.client.patch(self.url, {"signing_private_key": ""})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["signing_private_key_set"])

        connection.refresh_from_db()
        self.assertEqual(connection.signing_private_key, "")

    def test_key_must_be_a_32_byte_ed25519_key_once_decoded(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(self.url, {"signing_private_key": "not base64!"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        too_short = base64.b64encode(b"short").decode()
        response = self.client.patch(self.url, {"signing_private_key": too_short})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_bad_url_refused(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(self.url, {"base_url": "not-a-url"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_address_outside_the_cluster_is_rejected(self):
        self.client.force_authenticate(self.staff)
        for url in (
            "https://evil.example.com/",
            "http://203.0.113.5:8000",
            "http://harness.svc.example.com",
        ):
            response = self.client.patch(self.url, {"base_url": url})
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, url)

    def test_bare_hostname_rejected(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            self.url, {"base_url": "http://waldur-harness:8000"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class DefaultOffTest(test.APITestCase):
    def test_feature_is_off_until_switched_on(self):
        staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=staff)

        response = self.client.get(reverse("ai-reporting-message-list"))

        self.assertEqual(response.status_code, status.HTTP_424_FAILED_DEPENDENCY)


class PublicConfigurationTest(test.APITestCase):
    @override_constance_config(AI_REPORTING_LINK_DOMAINS="docs.isambard.ac.uk")
    def test_link_domains_reach_the_portal(self):
        self.client.force_authenticate(structure_factories.UserFactory())
        response = self.client.get("/api/configuration/")
        self.assertEqual(
            response.data["WALDUR_CORE"]["AI_REPORTING_LINK_DOMAINS"],
            "docs.isambard.ac.uk",
        )


def _access_token(user, scopes):
    expires_at = timezone.now() + datetime.timedelta(days=1)
    full_token, prefix, token_hash = PersonalAccessToken.generate_token(expires_at)
    PersonalAccessToken.objects.create(
        user=user,
        name="test",
        token_prefix=prefix,
        token_hash=token_hash,
        scopes=scopes,
        expires_at=expires_at,
    )
    return f"Bearer {full_token}"


@override_constance_config(AI_REPORTING_ENABLED=True, PAT_ENABLED=True)
class AccessTokenScopeTest(test.APITestCase):
    """A narrowly scoped access token of a staff user must not reach AI
    reporting: the harness reads all of Waldur."""

    connection_url = "/api/ai-reporting-harness-connection/"

    def setUp(self):
        cache.clear()
        self.staff = structure_factories.UserFactory(
            is_staff=True, can_use_personal_access_tokens=True
        )
        self.ask_url = reverse("ai-reporting-message-ask")

    def use(self, scopes):
        self.client.credentials(HTTP_AUTHORIZATION=_access_token(self.staff, scopes))

    def test_a_token_without_staff_scope_cannot_change_the_harness(self):
        self.use([PermissionEnum.LIST_ORDERS.value])
        response = self.client.patch(
            self.connection_url,
            {"base_url": "http://other.waldur-harness.svc:8000"},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_a_token_with_staff_scope_can_change_the_harness(self):
        self.use([PermissionEnum.STAFF_ACCESS.value])
        response = self.client.patch(
            self.connection_url,
            {"base_url": "http://other.waldur-harness.svc:8000"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_a_token_without_support_scope_cannot_ask_or_see_usage(self):
        self.use([PermissionEnum.LIST_ORDERS.value])
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            response = self.client.post(
                self.ask_url, {"prompt": "hi", "new_session": True}
            )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        response = self.client.get(reverse("ai-reporting-message-usage-stats"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_a_token_with_support_scope_can_ask(self):
        self.use([PermissionEnum.SUPPORT_ACCESS.value])
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            response = self.client.post(
                self.ask_url, {"prompt": "hi", "new_session": True}
            )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)


@override_constance_config(AI_REPORTING_ENABLED=True)
class PromptLengthTest(test.APITestCase):
    def test_a_very_long_question_is_refused(self):
        self.client.force_authenticate(structure_factories.UserFactory(is_staff=True))
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            response = self.client.post(
                reverse("ai-reporting-message-ask"),
                {"prompt": "x" * 10_001, "new_session": True},
            )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class FileDownloadAccessTest(test.APITestCase):
    """Downloading a file follows the same switch and roles as the API."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        session = ReportingSession.objects.create(user=self.user)
        message = ReportingMessage.objects.create(session=session, prompt="x")
        report = ReportingFile.objects.create(
            message=message, name="a.csv", file=ContentFile(b"a,b", name="a.csv")
        )
        self.stored = media_models.File.objects.get(name=report.file.name)

    def can_download(self, user=None):
        return media_access.user_can_access_file(self.stored, user or self.user)

    @override_constance_config(AI_REPORTING_ENABLED=True)
    def test_the_owner_can_download_while_allowed(self):
        self.assertTrue(self.can_download())
        self.assertFalse(
            self.can_download(structure_factories.UserFactory(is_staff=True))
        )

    @override_constance_config(AI_REPORTING_ENABLED=False)
    def test_not_while_the_feature_is_off(self):
        self.assertFalse(self.can_download())

    @override_constance_config(
        AI_REPORTING_ENABLED=True, AI_REPORTING_ENABLED_ROLES="staff"
    )
    def test_not_once_the_owners_role_is_no_longer_allowed(self):
        self.assertFalse(self.can_download())


@override_constance_config(AI_REPORTING_ENABLED=True)
class InvalidSessionFilterTest(test.APITestCase):
    def test_an_invalid_session_uuid_is_a_400(self):
        staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=staff)

        response = self.client.get(
            reverse("ai-reporting-message-list"), {"session": "not-a-uuid"}
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("session", response.data)


@override_constance_config(
    AI_REPORTING_ENABLED=True, AI_REPORTING_MAX_CONCURRENT_QUESTIONS=1
)
class AskConcurrencyLimitTest(test.APITestCase):
    """Each question holds a Celery worker, so only a few may run at once."""

    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=self.staff)
        self.ask_url = reverse("ai-reporting-message-ask")

    def _ask(self, **data):
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            return self.client.post(self.ask_url, {"prompt": "x", **data})

    def test_a_new_question_waits_while_others_are_running(self):
        other = structure_factories.UserFactory(is_staff=True)
        ReportingMessage.objects.create(
            session=ReportingSession.objects.create(user=other), prompt="busy"
        )

        response = self._ask(new_session=True)

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertFalse(ReportingMessage.objects.filter(prompt="x").exists())
        # Nor an empty conversation for it.
        self.assertFalse(ReportingSession.objects.filter(user=self.staff).exists())

    def test_asking_again_in_the_same_conversation_returns_the_running_one(self):
        session = ReportingSession.objects.create(user=self.staff)
        pending = ReportingMessage.objects.create(session=session, prompt="x")

        response = self._ask(session=str(session.uuid))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data["uuid"], str(pending.uuid))
