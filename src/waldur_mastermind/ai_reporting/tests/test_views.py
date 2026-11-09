import base64
from unittest import mock

from constance.test.unittest import override_config as override_constance_config
from django.core.files.base import ContentFile
from django.urls import reverse
from rest_framework import status, test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingFile,
    ReportingMessage,
    ReportingSession,
)


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
            session=session,
            prompt="earlier",
            status=ReportingMessage.Status.DONE,
            input_tokens=6,
            output_tokens=5,  # 11 >= 10
        )

        with mock.patch(
            "waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"
        ) as mock_delay:
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
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
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
        second = self.client.post(
            self.ask_url, {"prompt": "second, while first is pending"}
        )

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
            session=session,
            prompt="x",
            status=ReportingMessage.Status.DONE,
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


class EnabledRolesIntegrationTest(test.APITestCase):
    """Confirms permissions.check_enabled_roles is actually wired into the
    real endpoints (unit coverage of the check itself lives in
    test_permissions.py), and specifically that usage_stats is NOT affected
    by it - that endpoint stays staff/support-only regardless, since seeing
    every other user's usage is a different boundary than being allowed to
    use the tool at all."""

    def setUp(self):
        self.ask_url = reverse("ai-reporting-message-ask")
        self.usage_stats_url = reverse("ai-reporting-message-usage-stats")

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="disabled")
    def test_disabled_blocks_even_staff(self):
        staff = structure_factories.UserFactory(is_staff=True)
        self.client.force_authenticate(user=staff)
        response = self.client.post(self.ask_url, {"prompt": "hi"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="all")
    def test_all_lets_a_regular_user_ask(self):
        regular = structure_factories.UserFactory()
        self.client.force_authenticate(user=regular)
        with mock.patch("waldur_mastermind.ai_reporting.views.tasks.ask_harness.delay"):
            response = self.client.post(self.ask_url, {"prompt": "hi"})
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="all")
    def test_usage_stats_stays_staff_and_support_only_even_when_all_is_set(self):
        regular = structure_factories.UserFactory()
        self.client.force_authenticate(user=regular)
        response = self.client.get(self.usage_stats_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


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

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="all")
    def test_a_regular_user_can_list_and_delete_their_own_files_once_allowed(self):
        regular = structure_factories.UserFactory()
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

        # Every message aged out via AI_REPORTING_MESSAGE_RETENTION_DAYS leaves exactly
        # this behind: a session row with no messages left to preview.
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


class HarnessConnectionApiTest(test.APITestCase):
    """Same read/write split, and the same write-only-secret shape, as
    proposal_forms.tests.test_api.ConnectionApiTest for FormbricksConnection
    - this is the same kind of value, configured the same way."""

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
        response = self.client.patch(self.url, {"base_url": "http://x:8000"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        connection.refresh_from_db()
        self.assertEqual(connection.base_url, "http://x:8000")
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

    def test_bare_in_cluster_hostname_accepted(self):
        self.client.force_authenticate(self.staff)
        response = self.client.patch(
            self.url, {"base_url": "http://waldur-harness:8000"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
