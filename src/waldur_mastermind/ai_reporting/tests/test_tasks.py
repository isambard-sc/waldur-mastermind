import base64
import io
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

# The harness always streams.
_JSON = {"Content-Type": "application/x-ndjson"}


def _body(payload):
    """A fake stream ending in `payload` as the answer. Anything but a dict is
    sent as a line that isn't an event."""
    event = {"type": "done", **payload} if isinstance(payload, dict) else payload
    return lambda chunk_size: [json.dumps(event).encode() + b"\n"]


def _stream(mock_post, events):
    """Make the mocked harness stream `events` (dicts, or a generator of them)."""
    mock_post.return_value = mock.Mock(
        status_code=200,
        headers={"Content-Type": "application/x-ndjson"},
        iter_content=lambda chunk_size: (
            json.dumps(event).encode() + b"\n" for event in events
        ),
    )
    mock_post.return_value.raise_for_status = mock.Mock()


def _respond(mock_post, payload):
    """Make the mocked harness answer with `payload`."""
    mock_post.return_value = mock.Mock(
        status_code=200,
        headers=_JSON,
        iter_content=_body(payload),
    )
    mock_post.return_value.raise_for_status = mock.Mock()


_PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 20


def _file_response(content: bytes):
    response = mock.Mock(status_code=200, iter_content=lambda chunk_size: [content])
    response.raise_for_status = mock.Mock()
    return response


def _sent_body(mock_post) -> dict:
    _, kwargs = mock_post.call_args
    return json.loads(kwargs["data"])


def _set_signing_private_key(value: str) -> None:
    connection = HarnessConnection.get()
    connection.signing_private_key = value
    connection.save()


@override_constance_config(AI_REPORTING_ENABLED=True)
class AskHarnessTaskTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(
            session=self.session, prompt="How many projects are there?"
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_success_marks_done_and_stores_answer(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            headers=_JSON,
            iter_content=_body(
                {
                    "answer": "There are 26 projects.",
                    "new_files": ["a.png"],
                    "usage": {"input_tokens": 120, "output_tokens": 45},
                }
            ),
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
            headers=_JSON,
            iter_content=_body({"answer": "ok", "new_files": []}),
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
        """The user and session come from the message itself, never from the
        request. The session goes in the signed body."""
        mock_post.return_value = mock.Mock(
            status_code=200,
            headers=_JSON,
            iter_content=_body({"answer": "ok", "new_files": []}),
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["X-Waldur-User-Id"], str(self.user.uuid))
        self.assertEqual(json.loads(kwargs["data"])["session"], str(self.session.uuid))

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_without_a_signing_key_the_harness_is_not_called(self, mock_post):
        with mock.patch.object(
            HarnessConnection,
            "is_signing_configured",
            new_callable=mock.PropertyMock,
            return_value=False,
        ):
            ask_harness(self.message.pk)

        mock_post.assert_not_called()
        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        self.assertIn("signing key is missing", self.message.error_message)

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
            status_code=200,
            headers=_JSON,
            iter_content=_body({"answer": "ok", "new_files": []}),
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
    def test_the_harness_gets_a_deadline_inside_waldurs(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            headers=_JSON,
            iter_content=_body({"answer": "ok", "new_files": []}),
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["timeout"], (10, 360))
        self.assertEqual(json.loads(kwargs["data"])["deadline_seconds"], 540)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    @override_constance_config(
        AI_REPORTING_NAME="Bristol Bot",
        AI_REPORTING_CUSTOM_INSTRUCTIONS="Be terse.",
        AI_REPORTING_MAX_TURNS=5,
        AI_REPORTING_HISTORY_QUESTIONS=4,
    )
    def test_configured_overrides_are_sent_in_the_request_body(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            headers=_JSON,
            iter_content=_body({"answer": "ok", "new_files": []}),
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        body = json.loads(kwargs["data"])
        self.assertNotIn("model", body)
        self.assertEqual(body["name"], "Bristol Bot")
        self.assertEqual(body["custom_instructions"], "Be terse.")
        self.assertEqual(body["max_turns"], 5)
        self.assertEqual(body["history_questions"], 4)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_default_config_sends_only_settings_with_real_defaults(self, mock_post):
        """Unset settings are omitted."""
        mock_post.return_value = mock.Mock(
            status_code=200,
            headers=_JSON,
            iter_content=_body({"answer": "ok", "new_files": []}),
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertEqual(
            json.loads(kwargs["data"]),
            {
                "prompt": self.message.prompt,
                "session": str(self.session.uuid),
                "name": "Isambard Reporting Assistant",
                "deadline_seconds": 540,
                "max_turns": 25,
                "history_questions": 10,
            },
        )


@override_constance_config(AI_REPORTING_ENABLED=True)
class RecordUsageTest(test.APITestCase):
    """ask_harness leaves a usage record for every outcome, and it survives
    the message being deleted."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(
            session=self.session, prompt="How many projects are there?"
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_success_creates_a_done_usage_record_with_real_tokens(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            headers=_JSON,
            iter_content=_body(
                {
                    "answer": "26 projects.",
                    "new_files": [],
                    "usage": {"input_tokens": 120, "output_tokens": 45},
                }
            ),
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
            headers=_JSON,
            iter_content=_body(
                {
                    "answer": "ok",
                    "new_files": [],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }
            ),
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
            headers=_JSON,
            iter_content=_body(
                {
                    "answer": "ok",
                    "new_files": [],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                }
            ),
        )
        mock_post.return_value.raise_for_status = mock.Mock()
        ask_harness(self.message.pk)
        record_id = ReportingUsageRecord.objects.get(user=self.user).pk

        self.user.delete()

        record = ReportingUsageRecord.objects.get(pk=record_id)
        self.assertIsNone(record.user)
        self.assertEqual(record.input_tokens, 10)


@override_constance_config(AI_REPORTING_ENABLED=True)
class AskHarnessRobustnessTest(test.APITestCase):
    """Whatever the harness does, the message must end up done or failed,
    never stuck on pending."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
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
        connection.base_url = "http://harness.ns.svc:8000/"
        connection.save()
        _respond(mock_post, {"answer": "ok"})

        ask_harness(self.message.pk)

        args, _ = mock_post.call_args
        self.assertEqual(args[0], "http://harness.ns.svc:8000/query")

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


@override_constance_config(AI_REPORTING_ENABLED=True)
class StreamingTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    def _done(self, answer="ok"):
        return {
            "type": "done",
            "answer": answer,
            "new_files": [],
            "usage": {"input_tokens": 3, "output_tokens": 2},
        }

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_asks_for_a_stream(self, mock_post):
        _stream(mock_post, [self._done()])

        ask_harness(self.message.pk)

        _, kwargs = mock_post.call_args
        self.assertIn("application/x-ndjson", kwargs["headers"]["Accept"])
        self.assertIs(kwargs["stream"], True)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_streamed_answer_is_saved(self, mock_post):
        _stream(mock_post, [{"type": "progress", "text": "Working"}, self._done("26")])

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)
        self.assertEqual(self.message.answer, "26")
        self.assertEqual(self.message.input_tokens, 3)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_progress_is_visible_while_the_question_runs(self, mock_post):
        seen = []

        def events():
            yield {"type": "progress", "text": "Fetching projects from Waldur"}
            seen.append(ReportingMessage.objects.get(pk=self.message.pk).progress)
            yield self._done()

        _stream(mock_post, events())

        ask_harness(self.message.pk)

        self.assertEqual(seen, ["Fetching projects from Waldur"])

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_error_event_marks_failed(self, mock_post):
        _stream(mock_post, [{"type": "error", "error": "internal error"}])

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_stream_ending_without_an_answer_marks_failed(self, mock_post):
        _stream(mock_post, [{"type": "progress", "text": "Working"}])

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)

    @mock.patch("waldur_mastermind.ai_reporting.tasks._REQUEST_TIMEOUT_SECONDS", 60)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.time.monotonic")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_stream_running_past_the_timeout_fails(self, mock_post, monotonic):
        # Progress keeps arriving, but the whole question has taken too long.
        monotonic.side_effect = [0, 30, 61, 61]
        _stream(
            mock_post,
            [
                {"type": "progress", "text": "a"},
                {"type": "progress", "text": "b"},
                self._done(),
            ],
        )

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        self.assertIn("too long", self.message.error_message)

    @mock.patch("waldur_mastermind.ai_reporting.tasks._REQUEST_TIMEOUT_SECONDS", 60)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.time.monotonic")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_answer_arriving_just_after_the_deadline_is_kept(
        self, mock_post, monotonic
    ):
        monotonic.side_effect = [0, 61, 61]
        _stream(mock_post, [self._done()])

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)


@override_constance_config(AI_REPORTING_ENABLED=True)
class FileDownloadTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_files_are_fetched_from_the_messages_own_session(self, mock_post, mock_get):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png"]})
        mock_get.return_value = _file_response(_PNG)

        ask_harness(self.message.pk)

        args, _ = mock_get.call_args
        self.assertTrue(
            args[0].endswith(f"/files/chart.png?session={self.session.uuid}")
        )
        self.assertEqual(self.message.files.get().name, "chart.png")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_signature_covers_the_session_parameter(self, mock_post, mock_get):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png"]})
        mock_get.return_value = _file_response(_PNG)

        with mock.patch(
            "waldur_mastermind.ai_reporting.tasks.signing.sign_request",
            return_value={},
        ) as sign:
            ask_harness(self.message.pk)

        signed_paths = [call.args[1] for call in sign.call_args_list]
        self.assertIn(f"/files/chart.png?session={self.session.uuid}", signed_paths)


class FailStaleReportingMessagesTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)

    def _pending(self, minutes_old):
        """A pending message whose last progress was this long ago."""
        message = ReportingMessage.objects.create(session=self.session, prompt="x")
        ReportingMessage.objects.filter(pk=message.pk).update(
            created=timezone.now() - timedelta(minutes=minutes_old + 30),
            modified=timezone.now() - timedelta(minutes=minutes_old),
        )
        return message

    def test_long_pending_message_is_failed(self):
        message = self._pending(minutes_old=16)

        fail_stale_reporting_messages()

        message.refresh_from_db()
        self.assertEqual(message.status, ReportingMessage.Status.FAILED)
        self.assertTrue(message.error_message)
        self.assertEqual(ReportingUsageRecord.objects.count(), 1)

    def test_a_long_question_still_reporting_progress_is_left_alone(self):
        message = self._pending(minutes_old=12)

        fail_stale_reporting_messages()

        message.refresh_from_db()
        self.assertEqual(message.status, ReportingMessage.Status.PENDING)

    def test_recent_pending_message_is_left_alone(self):
        message = self._pending(minutes_old=5)

        fail_stale_reporting_messages()

        message.refresh_from_db()
        self.assertEqual(message.status, ReportingMessage.Status.PENDING)


@override_constance_config(AI_REPORTING_ENABLED=True)
class UntrustedHarnessResponseTest(test.APITestCase):
    """Waldur doesn't rely on the harness to behave: it may be compromised, or
    steered by text planted in Waldur data."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_redirect_is_not_followed(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=307, headers={"Location": "http://169.254.169.254/"}
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        self.assertIs(mock_post.call_args.kwargs["allow_redirects"], False)
        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_redirected_file_is_not_saved(self, mock_post, mock_get):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png"]})
        mock_get.return_value = mock.Mock(
            status_code=302, iter_content=lambda chunk_size: [_PNG]
        )
        mock_get.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        self.assertIs(mock_get.call_args.kwargs["allow_redirects"], False)
        self.assertFalse(self.message.files.exists())

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_only_safe_file_types_and_names_are_fetched(self, mock_post, mock_get):
        names = [
            "chart.svg",
            "page.html",
            "../x.png",
            ".hidden.csv",
            "a b.csv",
            "ok.csv",
        ]
        _respond(mock_post, {"answer": "ok", "new_files": names})
        mock_get.return_value = _file_response(b"a,b\n1,2\n")

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.new_files, ["ok.csv"])
        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(
            list(self.message.files.values_list("name", flat=True)), ["ok.csv"]
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_file_whose_content_does_not_match_its_type_is_dropped(
        self, mock_post, mock_get
    ):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png", "data.csv"]})
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
        mock_get.return_value = _file_response(svg)

        ask_harness(self.message.pk)

        self.assertFalse(self.message.files.exists())

    @mock.patch("waldur_mastermind.ai_reporting.tasks._MAX_FILE_BYTES", 100)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_an_oversized_file_is_dropped(self, mock_post, mock_get, *_):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png"]})
        mock_get.return_value = _file_response(_PNG + b"0" * 200)

        ask_harness(self.message.pk)

        self.assertFalse(self.message.files.exists())

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_the_number_of_files_is_capped(self, mock_post, mock_get):
        names = [f"chart{i}.png" for i in range(50)]
        _respond(mock_post, {"answer": "ok", "new_files": names})
        mock_get.return_value = _file_response(_PNG)

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(len(self.message.new_files), 20)
        self.assertEqual(self.message.files.count(), 20)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_huge_answer_is_cut_short(self, mock_post):
        _respond(mock_post, {"answer": "x" * 500_000, "new_files": []})

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(len(self.message.answer), 100_000)


class AccessRecheckedWhenTheQuestionRunsTest(test.APITestCase):
    """A question queued just before the feature was switched off, or before
    its asker lost their role, is not sent."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=session, prompt="x")

    def assert_not_sent(self, mock_post):
        ask_harness(self.message.pk)
        mock_post.assert_not_called()
        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)

    @override_constance_config(AI_REPORTING_ENABLED=False)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_feature_switched_off(self, mock_post):
        self.assert_not_sent(mock_post)

    @override_constance_config(
        AI_REPORTING_ENABLED=True, AI_REPORTING_ENABLED_ROLES="staff"
    )
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_role_no_longer_allowed(self, mock_post):
        self.assert_not_sent(mock_post)

    @override_constance_config(AI_REPORTING_ENABLED=True)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_user_deactivated(self, mock_post):
        self.user.is_active = False
        self.user.save()
        self.assert_not_sent(mock_post)


@override_constance_config(AI_REPORTING_ENABLED=True)
class MalformedResultTest(test.APITestCase):
    """A malformed result must still end the message, not leave it pending."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_huge_token_counts_are_capped(self, mock_post):
        _respond(
            mock_post,
            {
                "answer": "ok",
                "usage": {
                    "input_tokens": 2**40,
                    "output_tokens": 2**31,
                    "cache_read_tokens": 2**63,
                    "cache_write_tokens": 10**30,
                },
            },
        )

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)
        self.assertEqual(self.message.input_tokens, 10_000_000)
        record = ReportingUsageRecord.objects.get()
        self.assertEqual(record.cache_write_tokens, 10_000_000)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_non_numeric_token_counts_count_as_zero(self, mock_post):
        _respond(
            mock_post,
            {"answer": "ok", "usage": {"input_tokens": True, "output_tokens": 1.5}},
        )

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)
        self.assertEqual(self.message.input_tokens, 0)
        self.assertEqual(self.message.output_tokens, 0)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_new_files_that_is_not_a_list_is_ignored(self, mock_post, mock_get):
        for value in (5, True, {"chart.png": 1}):
            with self.subTest(new_files=value):
                message = ReportingMessage.objects.create(
                    session=self.session, prompt="x"
                )
                _respond(mock_post, {"answer": "ok", "new_files": value})

                ask_harness(message.pk)

                message.refresh_from_db()
                self.assertEqual(message.status, ReportingMessage.Status.DONE)
                self.assertEqual(message.new_files, [])
        mock_get.assert_not_called()

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_repeated_file_names_are_fetched_once(self, mock_post, mock_get):
        _respond(mock_post, {"answer": "ok", "new_files": ["a.png", "a.png"]})
        mock_get.return_value = _file_response(_PNG)

        ask_harness(self.message.pk)

        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(self.message.files.count(), 1)

    @mock.patch(
        "waldur_mastermind.ai_reporting.tasks._fetch_files",
        side_effect=RuntimeError("boom"),
    )
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_an_error_while_saving_the_result_marks_failed(self, mock_post, _):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png"]})

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)


@override_constance_config(AI_REPORTING_ENABLED=True)
class FilesReadyWhenDoneTest(test.APITestCase):
    """The frontend stops polling at done, so the files must already be
    there, and nothing new can be asked while they download."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_files_are_downloaded_while_the_message_is_still_pending(
        self, mock_post, mock_get
    ):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png"]})
        statuses = []

        def fetch(*args, **kwargs):
            statuses.append(ReportingMessage.objects.get(pk=self.message.pk).status)
            return _file_response(_PNG)

        mock_get.side_effect = fetch

        ask_harness(self.message.pk)

        self.assertEqual(statuses, [ReportingMessage.Status.PENDING])
        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)
        self.assertEqual(self.message.files.count(), 1)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_no_files_are_saved_for_a_message_that_was_already_failed(
        self, mock_post, mock_get
    ):
        _respond(mock_post, {"answer": "ok", "new_files": ["chart.png"]})

        def fetch(*args, **kwargs):
            # The stale check gives up on the message during the download.
            ReportingMessage.objects.filter(pk=self.message.pk).update(
                status=ReportingMessage.Status.FAILED
            )
            return _file_response(_PNG)

        mock_get.side_effect = fetch

        ask_harness(self.message.pk)

        self.assertFalse(self.message.files.exists())

    @mock.patch("waldur_mastermind.ai_reporting.tasks._FILES_DEADLINE_SECONDS", 10)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.time.monotonic")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_downloads_stop_at_the_files_deadline(
        self, mock_post, mock_get, monotonic, *_
    ):
        _respond(mock_post, {"answer": "ok", "new_files": ["a.png", "b.png"]})
        # Question deadline, download start, before a.png, before b.png.
        monotonic.side_effect = [0, 0, 0, 11]
        mock_get.return_value = _file_response(_PNG)

        ask_harness(self.message.pk)

        self.assertEqual(mock_get.call_count, 1)
        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.DONE)


@override_constance_config(AI_REPORTING_ENABLED=True)
class HarnessFailureUsageTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_tokens_used_before_a_harness_error_are_counted(self, mock_post):
        _stream(
            mock_post,
            [
                {
                    "type": "error",
                    "error": "internal error running the agent",
                    "usage": {"input_tokens": 700, "output_tokens": 30},
                }
            ],
        )

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        self.assertEqual(self.message.input_tokens, 700)
        record = ReportingUsageRecord.objects.get(user=self.user)
        self.assertEqual(record.status, ReportingUsageRecord.Status.FAILED)
        self.assertEqual((record.input_tokens, record.output_tokens), (700, 30))

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_bad_usage_in_a_harness_error_counts_as_zero(self, mock_post):
        _stream(mock_post, [{"type": "error", "error": "x", "usage": "lots"}])

        ask_harness(self.message.pk)

        record = ReportingUsageRecord.objects.get(user=self.user)
        self.assertEqual((record.input_tokens, record.output_tokens), (0, 0))

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_busy_harness_gets_its_own_message(self, mock_post):
        response = requests.Response()
        response.status_code = 429
        response.raw = io.BytesIO(b'{"error": "too many questions are running"}')
        mock_post.return_value = response

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual(self.message.status, ReportingMessage.Status.FAILED)
        self.assertIn("busy", self.message.error_message)


@override_constance_config(AI_REPORTING_ENABLED=True)
class RunningUsageTest(test.APITestCase):
    """The harness sends its token totals with each progress update, so they
    are counted even if the question then fails."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    def _progress(self, text, input_tokens, output_tokens=10):
        return {
            "type": "progress",
            "text": text,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_read_tokens": 5,
            },
        }

    def _record(self):
        return ReportingUsageRecord.objects.get(user=self.user)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_totals_are_saved_while_the_question_runs(self, mock_post):
        seen = []

        def events():
            yield self._progress("Fetching projects", 1000)
            seen.append(ReportingMessage.objects.get(pk=self.message.pk).input_tokens)
            yield {"type": "done", "answer": "ok", "usage": {"input_tokens": 1500}}

        _stream(mock_post, events())

        ask_harness(self.message.pk)

        self.assertEqual(seen, [1000])
        self.message.refresh_from_db()
        self.assertEqual(self.message.input_tokens, 1500)

    @mock.patch("waldur_mastermind.ai_reporting.tasks._REQUEST_TIMEOUT_SECONDS", 60)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.time.monotonic")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_timed_out_question_counts_the_tokens_spent(self, mock_post, monotonic):
        monotonic.side_effect = [0, 30, 61]
        _stream(
            mock_post,
            [self._progress("a", 1000), self._progress("b", 4000), {"type": "done"}],
        )

        ask_harness(self.message.pk)

        record = self._record()
        self.assertEqual(record.status, ReportingUsageRecord.Status.FAILED)
        self.assertEqual(record.input_tokens, 1000)
        self.assertEqual(record.cache_read_tokens, 5)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_stream_that_breaks_off_counts_the_tokens_spent(self, mock_post):
        _stream(mock_post, [self._progress("a", 1000), self._progress("b", 4000)])

        ask_harness(self.message.pk)

        self.assertEqual(self._record().input_tokens, 4000)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_an_error_events_own_totals_win(self, mock_post):
        _stream(
            mock_post,
            [
                self._progress("a", 1000),
                {"type": "error", "error": "x", "usage": {"input_tokens": 1200}},
            ],
        )

        ask_harness(self.message.pk)

        self.assertEqual(self._record().input_tokens, 1200)

    def test_a_lost_worker_still_counts_the_saved_totals(self):
        ReportingMessage.objects.filter(pk=self.message.pk).update(
            input_tokens=900,
            output_tokens=40,
            created=timezone.now() - timedelta(days=1),
            modified=timezone.now() - timedelta(days=1),
        )

        fail_stale_reporting_messages()

        record = self._record()
        self.assertEqual((record.input_tokens, record.output_tokens), (900, 40))


@override_constance_config(AI_REPORTING_ENABLED=True)
class TitleTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    def _answer_with_title(self, mock_post, title):
        _stream(mock_post, [{"type": "done", "answer": "ok", "title": title}])
        ask_harness(self.message.pk)
        self.message.refresh_from_db()
        return self.message.title

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_the_title_is_saved_on_one_line(self, mock_post):
        title = self._answer_with_title(mock_post, "  Active\nprojects   by org ")
        self.assertEqual(title, "Active projects by org")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_long_title_is_cut(self, mock_post):
        self.assertEqual(len(self._answer_with_title(mock_post, "x" * 500)), 100)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_title_that_is_not_text_is_ignored(self, mock_post):
        self.assertEqual(self._answer_with_title(mock_post, {"a": 1}), "")


@override_constance_config(AI_REPORTING_ENABLED=True)
class HarnessOutputBoundsTest(test.APITestCase):
    """A faulty or compromised harness can't exhaust a Waldur worker's memory."""

    def setUp(self):
        self.user = structure_factories.UserFactory(is_support=True)
        self.session = ReportingSession.objects.create(user=self.user)
        self.message = ReportingMessage.objects.create(session=self.session, prompt="x")

    def _failed(self):
        self.message.refresh_from_db()
        return self.message.status == ReportingMessage.Status.FAILED

    @mock.patch("waldur_mastermind.ai_reporting.tasks._MAX_LINE_BYTES", 100)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_line_that_never_ends_is_refused(self, mock_post):
        mock_post.return_value = mock.Mock(
            status_code=200,
            headers={"Content-Type": "application/x-ndjson"},
            iter_content=lambda chunk_size: (b"x" * 60 for _ in range(10)),
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        self.assertTrue(self._failed())

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_stalled_stream_counts_as_a_timeout(self, mock_post):
        def stalls(chunk_size):
            yield json.dumps({"type": "progress", "text": "Working"}).encode() + b"\n"
            raise requests.ConnectionError("Read timed out.")

        mock_post.return_value = mock.Mock(
            status_code=200,
            headers={"Content-Type": "application/x-ndjson"},
            iter_content=stalls,
        )
        mock_post.return_value.raise_for_status = mock.Mock()

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertIn("took too long", self.message.error_message)

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_nul_bytes_in_the_answer_are_dropped(self, mock_post):
        _respond(mock_post, {"answer": "a\x00b", "title": "t\x00", "new_files": []})

        ask_harness(self.message.pk)

        self.message.refresh_from_db()
        self.assertEqual((self.message.answer, self.message.title), ("ab", "t"))

    @mock.patch("waldur_mastermind.ai_reporting.tasks._MAX_TOTAL_FILE_BYTES", 30)
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.get")
    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.post")
    def test_a_messages_files_have_a_total_size_cap(self, mock_post, mock_get):
        _respond(mock_post, {"answer": "ok", "new_files": ["a.png", "b.png", "c.png"]})
        mock_get.side_effect = lambda *a, **k: _file_response(_PNG)

        ask_harness(self.message.pk)

        self.assertEqual(self.message.files.count(), 1)


class HarnessSettingsTest(test.APITestCase):
    @override_constance_config(AI_REPORTING_MAX_TURNS=-1)
    def test_an_old_minus_one_max_turns_leaves_the_harness_default(self):
        self.assertNotIn("max_turns", _harness_overrides())

    @override_constance_config(AI_REPORTING_MAX_TURNS=12)
    def test_a_real_max_turns_is_sent(self):
        self.assertEqual(_harness_overrides()["max_turns"], 12)
