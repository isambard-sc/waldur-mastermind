from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession


class ReportingSessionModelTest(test.APITestCase):
    def test_one_session_per_user(self):
        user = structure_factories.UserFactory()
        ReportingSession.objects.create(user=user)

        with self.assertRaises(Exception):  # IntegrityError, same as ChatSession
            ReportingSession.objects.create(user=user)

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
        self.assertFalse(
            ReportingMessage.objects.filter(pk=message.pk).exists()
        )
