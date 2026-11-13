from django.core.exceptions import ValidationError
from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingMessage,
    ReportingSession,
)


class ReportingSessionModelTest(test.APITestCase):
    def test_a_user_can_have_several_sessions(self):
        """Unlike chat's ChatSession, a user can have several sessions at once."""
        user = structure_factories.UserFactory()
        ReportingSession.objects.create(user=user)
        ReportingSession.objects.create(user=user)

        self.assertEqual(ReportingSession.objects.filter(user=user).count(), 2)

    def test_str(self):
        user = structure_factories.UserFactory(username="tanya")
        session = ReportingSession.objects.create(user=user)
        self.assertIn("tanya", str(session))


class ReportingMessageModelTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.session = ReportingSession.objects.create(user=self.user)

    def test_defaults_to_pending(self):
        message = ReportingMessage.objects.create(
            session=self.session, prompt="How many projects are there?"
        )
        self.assertEqual(message.status, ReportingMessage.Status.PENDING)
        self.assertEqual(message.answer, "")
        self.assertEqual(message.new_files, [])
        self.assertEqual(message.error_message, "")

    def test_ordered_by_creation(self):
        first = ReportingMessage.objects.create(session=self.session, prompt="first")
        second = ReportingMessage.objects.create(session=self.session, prompt="second")
        self.assertEqual(list(self.session.messages.all()), [first, second])

    def test_deleting_session_deletes_messages(self):
        message = ReportingMessage.objects.create(session=self.session, prompt="x")
        self.session.delete()
        self.assertFalse(ReportingMessage.objects.filter(pk=message.pk).exists())


class HarnessConnectionModelTest(test.APITestCase):
    def test_get_creates_the_one_row_on_first_use(self):
        self.assertEqual(HarnessConnection.objects.count(), 0)
        connection = HarnessConnection.get()
        self.assertEqual(HarnessConnection.objects.count(), 1)
        self.assertEqual(connection.pk, 1)

    def test_get_always_returns_the_same_row(self):
        """get() never creates a second row."""
        first = HarnessConnection.get()
        second = HarnessConnection.get()
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(HarnessConnection.objects.count(), 1)

    def test_default_base_url_points_at_the_in_cluster_service(self):
        """A new row works without configuration - the harness is always
        deployed at this address."""
        connection = HarnessConnection.get()
        self.assertEqual(
            connection.base_url,
            "http://waldur-harness.waldur-harness.svc.cluster.local:8000",
        )

    def test_signing_is_off_by_default(self):
        connection = HarnessConnection.get()
        self.assertEqual(connection.signing_private_key, "")
        self.assertFalse(connection.is_signing_configured)

    def test_is_signing_configured_once_a_key_is_set(self):
        connection = HarnessConnection.get()
        connection.signing_private_key = "ZmFrZS1rZXk="
        connection.save()
        self.assertTrue(connection.is_signing_configured)

    def test_rejects_a_url_with_no_host(self):
        connection = HarnessConnection.get()
        connection.base_url = "not-a-url"
        with self.assertRaises(ValidationError):
            connection.full_clean()

    def test_accepts_a_bare_in_cluster_hostname(self):
        """Django's URLValidator would reject this, since it has no dot."""
        connection = HarnessConnection.get()
        connection.base_url = "http://waldur-harness:8000"
        connection.full_clean()  # must not raise
