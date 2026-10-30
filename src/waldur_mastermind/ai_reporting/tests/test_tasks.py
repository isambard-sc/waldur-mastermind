from unittest import mock

import requests
from constance.test.unittest import override_config as override_constance_config
from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession
from waldur_mastermind.ai_reporting.tasks import _harness_overrides, ask_harness


class AskHarnessTaskTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(
            session=self.session, prompt="How many projects are there?"
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_success_marks_done_and_stores_answer(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            json=lambda: {
                "answer": "There are 26 projects.", "new_files": ["a.png"],
                "usage": {"input_tokens": 120, "output_tokens": 45},
            },
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)
        self.assertEqual(self.message.answer, "There are 26 projects.")
        self.assertEqual(self.message.new_files, ["a.png"])
        self.assertEqual(self.message.input_tokens, 120)
        self.assertEqual(self.message.output_tokens, 45)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_missing_usage_defaults_to_zero(self, mock_post):
        """A harness response with no "usage" key at all (shouldn't happen
        post-upgrade, but a stale harness pod or a transient bug shouldn't
        crash the task) must not raise - zero is the honest answer when the
        cost of this call isn't known."""
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []},
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.input_tokens, 0)
        self.assertEqual(self.message.output_tokens, 0)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_identity_headers_use_the_authenticated_users_and_sessions_real_uuids(
        self, mock_post
    ):
        """Never derive these headers from anything but the message's own
        session/user - this is the whole IDOR protection for the harness
        call. The session uuid is what the harness actually keys its
        conversation store on - see http_service.py."""
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["X-Waldur-User-Id"], str(self.user.uuid))
        self.assertEqual(
            kwargs["headers"]["X-Waldur-Session-Id"], str(self.session.uuid)
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_network_failure_marks_failed_not_stuck_pending(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("connection refused")

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        self.assertIn("connection refused", self.message.error_message)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_harness_error_status_marks_failed(self, mock_post):
        response = requests.Response()
        response.status_code = 500
        mock_post.return_value = response

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)

    def test_missing_message_does_not_raise(self):
        ask_harness(999999)  # just must not blow up the Celery worker

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    @override_constance_config(AI_REPORTING_REQUEST_TIMEOUT_SECONDS=42)
    def test_request_timeout_is_constance_driven(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["timeout"], 42)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    @override_constance_config(
        AI_REPORTING_MODEL="custom-model", AI_REPORTING_NAME="Bristol Bot",
        AI_REPORTING_CUSTOM_INSTRUCTIONS="Be terse.",
        AI_REPORTING_MAX_TURNS=5, AI_REPORTING_HISTORY_LIMIT=10,
    )
    def test_configured_overrides_are_sent_in_the_request_body(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"]["model"], "custom-model")
        self.assertEqual(kwargs["json"]["name"], "Bristol Bot")
        self.assertEqual(kwargs["json"]["custom_instructions"], "Be terse.")
        self.assertEqual(kwargs["json"]["max_turns"], 5)
        self.assertEqual(kwargs["json"]["history_limit"], 10)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_default_config_sends_only_the_name_override(self, mock_post):
        """Model/custom_instructions/max_turns/history_limit all default to
        "no override" (empty string / -1) and must be omitted. Name is the
        one exception: its Constance default is a real, non-empty value
        (deliberately kept identical to run_agent.DEFAULT_ASSISTANT_NAME, so
        sending it is always a harmless no-op) - it's only actually omitted
        once an admin clears it to "" to explicitly defer to the harness's
        own default instead."""
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["json"],
            {"prompt": self.message.prompt, "name": "Isambard Reporting Assistant"},
        )


class HarnessOverridesTest(test.APITestCase):
    @override_constance_config(
        AI_REPORTING_MODEL="", AI_REPORTING_NAME="",
        AI_REPORTING_CUSTOM_INSTRUCTIONS="",
        AI_REPORTING_MAX_TURNS=-1, AI_REPORTING_HISTORY_LIMIT=-1,
    )
    def test_empty_defaults_produce_no_overrides(self):
        self.assertEqual(_harness_overrides(), {})

    @override_constance_config(AI_REPORTING_MODEL="anthropic.claude-opus-5-5", AI_REPORTING_NAME="")
    def test_model_override_included_when_set(self):
        self.assertEqual(_harness_overrides(), {"model": "anthropic.claude-opus-5-5"})

    @override_constance_config(AI_REPORTING_MAX_TURNS=0, AI_REPORTING_NAME="")
    def test_max_turns_zero_is_a_real_override_not_treated_as_unset(self):
        """0 is a valid (if extreme) turn limit - only -1 means 'no
        override', so this must not be confused with the unset sentinel."""
        self.assertEqual(_harness_overrides(), {"max_turns": 0})
