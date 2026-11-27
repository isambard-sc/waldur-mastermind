from unittest import mock

from constance.test.unittest import override_config as override_constance_config
from django.core.exceptions import ValidationError
from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting import media_access
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingFile,
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
        user = structure_factories.UserFactory(username="analyst")
        session = ReportingSession.objects.create(user=user)
        self.assertIn("analyst", str(session))


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

    def test_accepts_a_cluster_service_address(self):
        connection = HarnessConnection.get()
        for url in (
            "http://waldur-harness.waldur-harness.svc.cluster.local:8000",
            "http://waldur-harness.waldur-harness.svc:8000",
        ):
            connection.base_url = url
            connection.full_clean()  # must not raise

    def test_rejects_anything_but_a_cluster_service_address(self):
        """Including tricks where the check and requests disagree on the host."""
        connection = HarnessConnection.get()
        for url in (
            "http://evil.com\\@waldur-harness.waldur-harness.svc:8000",
            "http://user@waldur-harness.waldur-harness.svc:8000",
            "http://waldur-harness:8000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://2852039166",
            "http://0x7f000001",
            "http://[fd00:ec2::254]",
            "http://metadata.google.internal",
            "http://redis:6379",
            "http://waldur-harness.waldur-harness.svc.:8000",
            "http://waldur-harness.waldur-harness.svc:8000/?x=1",
            "http://waldur-harness.waldur-harness.svc:8000/#x",
            "ftp://waldur-harness.waldur-harness.svc",
        ):
            connection.base_url = url
            with self.assertRaises(ValidationError, msg=url):
                connection.full_clean()


class HarnessEndpointTest(test.APITestCase):
    def test_a_stored_outside_address_is_never_used(self):
        """A value saved before the validator existed still can't be called."""
        connection = HarnessConnection.get()
        HarnessConnection.objects.filter(pk=connection.pk).update(
            base_url="https://evil.example.com"
        )
        connection.refresh_from_db()

        with self.assertRaises(ValueError):
            connection.endpoint("/query")

    def test_in_cluster_addresses_are_used(self):
        connection = HarnessConnection.get()
        for url in (
            "http://waldur-harness.waldur-harness.svc.cluster.local:8000",
            "http://waldur-harness.waldur-harness.svc:8000",
        ):
            connection.base_url = url
            self.assertEqual(connection.endpoint("/query"), url + "/query")

    def test_a_stored_bypass_address_is_never_used(self):
        connection = HarnessConnection.get()
        HarnessConnection.objects.filter(pk=connection.pk).update(
            base_url="http://evil.com\\@waldur-harness.waldur-harness.svc:8000"
        )
        connection.refresh_from_db()

        with self.assertRaises(ValueError):
            connection.endpoint("/query")


class ReportingFileMediaAccessTest(test.APITestCase):
    @override_constance_config(AI_REPORTING_ENABLED=True)
    def test_an_access_token_without_the_support_scope_gets_no_files(self):
        staff = structure_factories.UserFactory(is_staff=True)
        session = ReportingSession.objects.create(user=staff)
        message = ReportingMessage.objects.create(session=session, prompt="x")
        ReportingFile.objects.create(
            message=message, name="a.csv", file="ai_reporting/a.csv"
        )
        request = mock.Mock(user=staff)

        with mock.patch.object(
            media_access, "check_pat_support_scope", return_value=False
        ):
            self.assertFalse(
                media_access._own_files(ReportingFile.objects.all(), request).exists()
            )
        with mock.patch.object(
            media_access, "check_pat_support_scope", return_value=True
        ):
            self.assertTrue(
                media_access._own_files(ReportingFile.objects.all(), request).exists()
            )
        # Without a request (the rule is also called with the user), only the role counts.
        self.assertTrue(
            media_access._own_files(ReportingFile.objects.all(), staff).exists()
        )
