import base64
from datetime import timedelta
from unittest import mock

import requests
from constance.test.unittest import override_config as override_constance_config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.utils import timezone
from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting import signing, tasks
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingMessage,
    ReportingSession,
)

_DELAY = "waldur_mastermind.ai_reporting.handlers.tasks.delete_harness_session.delay"


class DeletingAConversationClearsTheHarnessTest(test.APITestCase):
    """The harness keeps each conversation's history and fetched data, so it
    is asked to delete them whenever Waldur deletes the conversation."""

    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)

    @mock.patch(_DELAY)
    def test_deleting_a_conversation(self, delay):
        with self.captureOnCommitCallbacks(execute=True):
            self.session.delete()

        delay.assert_called_once_with(str(self.user.uuid), str(self.session.uuid))

    @mock.patch(_DELAY)
    def test_deleting_a_user(self, delay):
        with self.captureOnCommitCallbacks(execute=True):
            self.user.delete()

        delay.assert_called_once_with(str(self.user.uuid), str(self.session.uuid))

    @mock.patch(_DELAY)
    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_retention_clean_up(self, delay):
        long_ago = timezone.now() - timedelta(days=100)
        ReportingSession.objects.filter(pk=self.session.pk).update(created=long_ago)
        message = ReportingMessage.objects.create(session=self.session, prompt="x")
        ReportingMessage.objects.filter(pk=message.pk).update(
            created=long_ago, status=ReportingMessage.Status.DONE
        )

        with self.captureOnCommitCallbacks(execute=True):
            tasks.cleanup_old_reporting_messages()

        delay.assert_called_once_with(str(self.user.uuid), str(self.session.uuid))


class DeleteHarnessSessionTaskTest(test.APITestCase):
    def setUp(self):
        connection = HarnessConnection.get()
        self.private_key = Ed25519PrivateKey.generate()
        connection.signing_private_key = base64.b64encode(
            self.private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode()
        connection.save()

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.delete")
    def test_sends_a_signed_delete_for_that_conversation(self, mock_delete):
        mock_delete.return_value = mock.Mock(status_code=200)

        tasks.delete_harness_session("user-uuid", "session-uuid")

        url = mock_delete.call_args.args[0]
        headers = mock_delete.call_args.kwargs["headers"]
        self.assertTrue(url.endswith("/sessions/session-uuid"))
        self.assertEqual(headers["X-Waldur-User-Id"], "user-uuid")
        self.assertIs(mock_delete.call_args.kwargs["allow_redirects"], False)
        message = signing._canonical_message(
            headers["X-Waldur-Signature-Timestamp"],
            "user-uuid",
            "/sessions/session-uuid",
            b"",
        )
        self.private_key.public_key().verify(
            base64.b64decode(headers["X-Waldur-Signature"]), message
        )

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.delete")
    def test_an_unreachable_harness_is_retried(self, mock_delete):
        mock_delete.side_effect = requests.ConnectionError("refused")

        with self.assertRaises(tasks._RetryDelete):
            tasks.delete_harness_session("user-uuid", "session-uuid")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.delete")
    def test_a_busy_or_failing_harness_is_retried(self, mock_delete):
        for status_code in (409, 503):
            mock_delete.return_value = mock.Mock(status_code=status_code)
            with self.assertRaises(tasks._RetryDelete):
                tasks.delete_harness_session("user-uuid", "session-uuid")

    @mock.patch("waldur_mastermind.ai_reporting.tasks.requests.delete")
    def test_a_refused_delete_is_logged_not_retried(self, mock_delete):
        response = requests.Response()
        response.status_code = 401
        mock_delete.return_value = response

        with self.assertLogs("waldur_mastermind.ai_reporting.tasks", "ERROR"):
            tasks.delete_harness_session("user-uuid", "session-uuid")
