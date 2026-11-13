import base64
import json
from datetime import timedelta
from unittest import mock

import requests
from constance.test.unittest import override_config as override_constance_config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.utils import timezone
from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting import signing
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingMessage,
    ReportingSession,
    ReportingUsageRecord,
)
from waldur_mastermind.ai_reporting.tasks import (
    _harness_overrides,
    ask_harness,
    fail_stale_reporting_messages,
)


def _respond(mock_post, payload):
    """Make the mocked harness return `payload` as its JSON body."""
    mock_post.return_value = mock.Mock(status_code=200, json=lambda: payload)
    mock_post.return_value.raise_for_status = mock.Mock()


def _sent_body(mock_post) -> dict:
    _, kwargs = mock_post.call_args
    return json.loads(kwargs["data"])


def _set_signing_private_key(value: str) -> None:
    connection = HarnessConnection.get()
    connection.signing_private_key = value
    connection.save()


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
                "answer": "There are 26 projects.",
                "new_files": ["a.png"],
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
        """A response without "usage" (e.g. from an older harness) records 0,
        not an error."""
        mock_post.return_value = mock.Mock(
            status_code=200,
            json=lambda: {"answer": "ok", "new_files": []},
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
        """Headers come from the message's own session and user, never from
        the request."""
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
    def test_request_is_unsigned_when_no_signing_key_configured(self, mock_post):
        _set_signing_private_key("")
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertNotIn("X-Waldur-Signature", kwargs["headers"])
        self.assertNotIn("X-Waldur-Signature-Timestamp", kwargs["headers"])

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_request_is_signed_when_a_signing_key_is_configured(self, mock_post):
        private_key = Ed25519PrivateKey.generate()
        private_b64 = base64.b64encode(
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode()

        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        _set_signing_private_key(private_b64)
        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertIn("X-Waldur-Signature", kwargs["headers"])
        self.assertIn("X-Waldur-Signature-Timestamp", kwargs["headers"])
        # The signature must cover exactly the bytes sent.
        public_key = private_key.public_key()
        message = signing._canonical_message(
            kwargs["headers"]["X-Waldur-Signature-Timestamp"],
            str(self.user.uuid),
            "/query",
            kwargs["data"],
        )
        public_key.verify(
            base64.b64decode(kwargs["headers"]["X-Waldur-Signature"]), message
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_network_failure_marks_failed_not_stuck_pending(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("connection refused")

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        # Users get a generic message; the details only go to the log.
        self.assertNotIn("connection refused", self.message.error_message)
        self.assertNotIn("http", self.message.error_message)

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
        AI_REPORTING_MODEL="custom-model",
        AI_REPORTING_NAME="Bristol Bot",
        AI_REPORTING_CUSTOM_INSTRUCTIONS="Be terse.",
        AI_REPORTING_MAX_TURNS=5,
        AI_REPORTING_HISTORY_LIMIT=10,
    )
    def test_configured_overrides_are_sent_in_the_request_body(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        body = json.loads(kwargs["data"])
        self.assertEqual(body["model"], "custom-model")
        self.assertEqual(body["name"], "Bristol Bot")
        self.assertEqual(body["custom_instructions"], "Be terse.")
        self.assertEqual(body["max_turns"], 5)
        self.assertEqual(body["history_limit"], 10)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_default_config_sends_only_the_name_override(self, mock_post):
        """Unset overrides are omitted. Name is sent by default because its
        setting has a real default value."""
        mock_post.return_value = mock.Mock(
            status_code=200, json=lambda: {"answer": "ok", "new_files": []}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(
            json.loads(kwargs["data"]),
            {
                "prompt": self.message.prompt,
                "name": "Isambard Reporting Assistant",
                "new_session": True,
            },
        )


class RecordUsageTest(test.APITestCase):
    """ask_harness leaves a usage record for every outcome, and it survives
    the message being deleted."""

    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(
            session=self.session, prompt="How many projects are there?"
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_success_creates_a_done_usage_record_with_real_tokens(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            json=lambda: {
                "answer": "26 projects.",
                "new_files": [],
                "usage": {"input_tokens": 120, "output_tokens": 45},
            },
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        record = ReportingUsageRecord.objects.get(user=self.user)
        self.assertEqual(record.status, ReportingUsageRecord.Status.DONE)
        self.assertEqual(record.input_tokens, 120)
        self.assertEqual(record.output_tokens, 45)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_network_failure_still_creates_a_failed_usage_record(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("connection refused")

        ask_harness(self.message.pk)

        record = ReportingUsageRecord.objects.get(user=self.user)
        self.assertEqual(record.status, ReportingUsageRecord.Status.FAILED)
        self.assertEqual(record.input_tokens, 0)
        self.assertEqual(record.output_tokens, 0)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_bad_response_status_still_creates_a_failed_usage_record(self, mock_post):
        response = requests.Response()
        response.status_code = 500
        mock_post.return_value = response

        ask_harness(self.message.pk)

        record = ReportingUsageRecord.objects.get(user=self.user)
        self.assertEqual(record.status, ReportingUsageRecord.Status.FAILED)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_usage_record_survives_the_message_being_deleted(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            json=lambda: {
                "answer": "ok",
                "new_files": [],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)
        self.message.delete()

        record = ReportingUsageRecord.objects.get(user=self.user)
        self.assertEqual(record.input_tokens, 10)
        self.assertEqual(record.output_tokens, 5)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_usage_record_survives_the_user_being_deleted(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            json=lambda: {
                "answer": "ok",
                "new_files": [],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )
        mock_post.return_value.raise_for_status = mock.Mock()
        ask_harness(self.message.pk)
        record_id = ReportingUsageRecord.objects.get(user=self.user).pk

        self.user.delete()

        record = ReportingUsageRecord.objects.get(pk=record_id)
        self.assertIsNone(record.user)
        self.assertEqual(record.input_tokens, 10)


class AskHarnessRobustnessTest(test.APITestCase):
    """Whatever the harness does, the message must end up done or failed,
    never stuck on pending."""

    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(
            session=self.session, prompt="How many projects are there?"
        )

    def _status(self):
        self.message.refresh_from_db()
        return self.message.status

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_non_object_json_marks_failed(self, mock_post):
        _respond(mock_post, ["not", "an", "object"])

        ask_harness(self.message.pk)

        self.assertEqual(self._status(), ReportingMessage.Status.FAILED)
        self.assertEqual(ReportingUsageRecord.objects.count(), 1)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_null_fields_are_treated_as_empty(self, mock_post):
        _respond(
            mock_post,
            {"answer": None, "new_files": None, "usage": {"input_tokens": None}},
        )

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)
        self.assertEqual(self.message.answer, "")
        self.assertEqual(self.message.new_files, [])
        self.assertEqual(self.message.input_tokens, 0)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_unexpected_error_marks_failed(self, mock_post):
        mock_post.side_effect = RuntimeError("something nobody planned for")

        ask_harness(self.message.pk)

        self.assertEqual(self._status(), ReportingMessage.Status.FAILED)
        self.assertEqual(ReportingUsageRecord.objects.count(), 1)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_timeout_gets_its_own_message(self, mock_post):
        mock_post.side_effect = requests.Timeout()

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        self.assertIn("too long", self.message.error_message)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_already_finished_message_is_skipped(self, mock_post):
        self.message.status = ReportingMessage.Status.FAILED
        self.message.save()

        ask_harness(self.message.pk)

        mock_post.assert_not_called()

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_answer_arriving_after_the_message_was_failed_is_dropped(self, mock_post):
        def fail_it_meanwhile(*args, **kwargs):
            ReportingMessage.objects.filter(pk=self.message.pk).update(
                status=ReportingMessage.Status.FAILED
            )
            return mock.DEFAULT

        _respond(mock_post, {"answer": "late", "usage": {"input_tokens": 5}})
        mock_post.side_effect = fail_it_meanwhile

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        self.assertEqual(self.message.answer, "")
        self.assertEqual(ReportingUsageRecord.objects.count(), 0)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_trailing_slash_in_base_url_is_handled(self, mock_post):
        connection = HarnessConnection.get()
        connection.base_url = "http://harness:8000/"
        connection.save()
        _respond(mock_post, {"answer": "ok"})

        ask_harness(self.message.pk)

        args, _ = mock_post.call_args
        self.assertEqual(args[0], "http://harness:8000/query")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_cache_tokens_are_recorded(self, mock_post):
        _respond(
            mock_post,
            {
                "answer": "ok",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "cache_read_tokens": 4000,
                    "cache_write_tokens": 300,
                },
            },
        )

        ask_harness(self.message.pk)

        record = ReportingUsageRecord.objects.get()
        self.assertEqual(record.cache_read_tokens, 4000)
        self.assertEqual(record.cache_write_tokens, 300)


class NewSessionTest(test.APITestCase):
    """The first question in a session tells the harness to start a fresh
    conversation."""

    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)

    def _ask(self, mock_post, prompt):
        message = ReportingMessage.objects.create(session=self.session, prompt=prompt)
        _respond(mock_post, {"answer": "ok"})
        ask_harness(message.pk)
        return _sent_body(mock_post)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_first_question_starts_a_new_harness_conversation(self, mock_post):
        self.assertIs(self._ask(mock_post, "first")["new_session"], True)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_follow_up_continues_the_conversation(self, mock_post):
        self._ask(mock_post, "first")
        self.assertNotIn("new_session", self._ask(mock_post, "follow-up"))

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_question_after_a_failed_first_one_still_starts_fresh(self, mock_post):
        ReportingMessage.objects.create(
            session=self.session, prompt="x", status=ReportingMessage.Status.FAILED
        )
        self.assertIs(self._ask(mock_post, "retry")["new_session"], True)


class FailStaleReportingMessagesTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)

    def _pending(self, minutes_old):
        message = ReportingMessage.objects.create(session=self.session, prompt="x")
        ReportingMessage.objects.filter(pk=message.pk).update(
            created=timezone.now() - timedelta(minutes=minutes_old)
        )
        return message

    @override_constance_config(AI_REPORTING_REQUEST_TIMEOUT_SECONDS=600)
    def test_long_pending_message_is_failed(self):
        message = self._pending(minutes_old=30)

        fail_stale_reporting_messages()

        message.refresh_from_db()
        self.assertEqual(message.status, ReportingMessage.Status.FAILED)
        self.assertTrue(message.error_message)
        self.assertEqual(ReportingUsageRecord.objects.count(), 1)

    @override_constance_config(AI_REPORTING_REQUEST_TIMEOUT_SECONDS=600)
    def test_recent_pending_message_is_left_alone(self):
        message = self._pending(minutes_old=5)

        fail_stale_reporting_messages()

        message.refresh_from_db()
        self.assertEqual(message.status, ReportingMessage.Status.PENDING)


class HarnessOverridesTest(test.APITestCase):
    @override_constance_config(
        AI_REPORTING_MODEL="",
        AI_REPORTING_NAME="",
        AI_REPORTING_CUSTOM_INSTRUCTIONS="",
        AI_REPORTING_MAX_TURNS=-1,
        AI_REPORTING_HISTORY_LIMIT=-1,
    )
    def test_empty_defaults_produce_no_overrides(self):
        self.assertEqual(_harness_overrides(), {})

    @override_constance_config(
        AI_REPORTING_MODEL="anthropic.claude-opus-5-5", AI_REPORTING_NAME=""
    )
    def test_model_override_included_when_set(self):
        self.assertEqual(_harness_overrides(), {"model": "anthropic.claude-opus-5-5"})

    @override_constance_config(AI_REPORTING_MAX_TURNS=0, AI_REPORTING_NAME="")
    def test_max_turns_zero_is_a_real_override_not_treated_as_unset(self):
        """0 is a real limit; only -1 means no override."""
        self.assertEqual(_harness_overrides(), {"max_turns": 0})
