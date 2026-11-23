from datetime import timedelta
from unittest import mock

from constance.test.unittest import override_config as override_constance_config
from django.core.files.base import ContentFile
from django.utils import timezone
from rest_framework import test

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting import tasks
from waldur_mastermind.ai_reporting.models import (
    ReportingFile,
    ReportingMessage,
    ReportingSession,
)


class MessageCleanupTest(test.APITestCase):
    def setUp(self):
        user = structure_factories.UserFactory()
        session = ReportingSession.objects.create(user=user)
        now = timezone.now()

        self.recent_message = ReportingMessage.objects.create(
            session=session, prompt="recent"
        )
        ReportingMessage.objects.filter(pk=self.recent_message.pk).update(
            created=now - timedelta(days=10), status=ReportingMessage.Status.DONE
        )

        self.old_message = ReportingMessage.objects.create(
            session=session, prompt="old"
        )
        ReportingMessage.objects.filter(pk=self.old_message.pk).update(
            created=now - timedelta(days=100), status=ReportingMessage.Status.DONE
        )

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_cleanup_deletes_only_old_messages(self):
        result = tasks.cleanup_old_reporting_messages()

        self.assertEqual(result, {"status": "ok", "deleted_count": 1})
        self.assertTrue(
            ReportingMessage.objects.filter(pk=self.recent_message.pk).exists()
        )
        self.assertFalse(
            ReportingMessage.objects.filter(pk=self.old_message.pk).exists()
        )

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=-1)
    def test_cleanup_disabled(self):
        result = tasks.cleanup_old_reporting_messages()

        self.assertEqual(result, {"status": "disabled", "deleted_count": 0})
        self.assertEqual(ReportingMessage.objects.count(), 2)

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_cleanup_cascades_to_attached_files_and_frees_their_bytes(self):
        reporting_file = ReportingFile.objects.create(
            message=self.old_message,
            name="chart.png",
            file=ContentFile(b"fake png bytes", name="chart.png"),
        )
        stored_file = reporting_file.file

        tasks.cleanup_old_reporting_messages()

        self.assertFalse(ReportingFile.objects.filter(pk=reporting_file.pk).exists())
        self.assertFalse(stored_file.storage.exists(stored_file.name))

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_nothing_to_delete_is_not_an_error(self):
        ReportingMessage.objects.filter(pk=self.old_message.pk).delete()
        result = tasks.cleanup_old_reporting_messages()
        self.assertEqual(result, {"status": "ok", "deleted_count": 0})


class FileCleanupTest(test.APITestCase):
    def setUp(self):
        user = structure_factories.UserFactory()
        session = ReportingSession.objects.create(user=user)
        self.message = ReportingMessage.objects.create(session=session, prompt="x")
        now = timezone.now()

        self.recent_file = ReportingFile.objects.create(
            message=self.message,
            name="recent.png",
            file=ContentFile(b"recent bytes", name="recent.png"),
        )
        ReportingFile.objects.filter(pk=self.recent_file.pk).update(
            created=now - timedelta(days=5)
        )

        self.old_file = ReportingFile.objects.create(
            message=self.message,
            name="old.png",
            file=ContentFile(b"old bytes", name="old.png"),
        )
        ReportingFile.objects.filter(pk=self.old_file.pk).update(
            created=now - timedelta(days=30)
        )

    @override_constance_config(AI_REPORTING_FILE_RETENTION_DAYS=21)
    def test_cleanup_deletes_only_old_files_and_keeps_the_message(self):
        old_stored_file = ReportingFile.objects.get(pk=self.old_file.pk).file

        result = tasks.cleanup_old_reporting_files()

        self.assertEqual(result, {"status": "ok", "deleted_count": 1})
        self.assertTrue(ReportingFile.objects.filter(pk=self.recent_file.pk).exists())
        self.assertFalse(ReportingFile.objects.filter(pk=self.old_file.pk).exists())
        self.assertFalse(old_stored_file.storage.exists(old_stored_file.name))
        # The message stays - file retention is separate from message retention.
        self.assertTrue(ReportingMessage.objects.filter(pk=self.message.pk).exists())

    @override_constance_config(AI_REPORTING_FILE_RETENTION_DAYS=-1)
    def test_cleanup_disabled(self):
        result = tasks.cleanup_old_reporting_files()

        self.assertEqual(result, {"status": "disabled", "deleted_count": 0})
        self.assertEqual(ReportingFile.objects.count(), 2)

    @override_constance_config(AI_REPORTING_FILE_RETENTION_DAYS=21)
    def test_cleanup_processes_more_than_one_chunk(self):
        """Deletes everything, not just the first chunk."""
        now = timezone.now()
        for i in range(tasks._FILE_CLEANUP_CHUNK_SIZE + 5):
            extra = ReportingFile.objects.create(
                message=self.message,
                name=f"extra-{i}.png",
                file=ContentFile(b"x", name=f"extra-{i}.png"),
            )
            ReportingFile.objects.filter(pk=extra.pk).update(
                created=now - timedelta(days=30)
            )

        result = tasks.cleanup_old_reporting_files()

        self.assertEqual(
            result["deleted_count"], tasks._FILE_CLEANUP_CHUNK_SIZE + 5 + 1
        )  # +1 is self.old_file
        self.assertTrue(ReportingFile.objects.filter(pk=self.recent_file.pk).exists())


class MessageCleanupBatchesTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.long_ago = timezone.now() - timedelta(days=100)

    def _old_session(self, messages):
        session = ReportingSession.objects.create(user=self.user)
        ReportingSession.objects.filter(pk=session.pk).update(created=self.long_ago)
        for i in range(messages):
            message = ReportingMessage.objects.create(session=session, prompt=str(i))
            ReportingMessage.objects.filter(pk=message.pk).update(
                created=self.long_ago, status=ReportingMessage.Status.DONE
            )
        return session

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_old_messages_are_deleted_in_chunks(self):
        self._old_session(messages=5)

        with mock.patch.object(tasks, "_MESSAGE_CLEANUP_CHUNK_SIZE", 2):
            result = tasks.cleanup_old_reporting_messages()

        self.assertEqual(result, {"status": "ok", "deleted_count": 5})
        self.assertFalse(ReportingMessage.objects.exists())

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_a_question_still_running_is_kept(self):
        session = self._old_session(messages=0)
        message = ReportingMessage.objects.create(session=session, prompt="running")
        ReportingMessage.objects.filter(pk=message.pk).update(created=self.long_ago)

        tasks.cleanup_old_reporting_messages()

        self.assertTrue(ReportingMessage.objects.filter(pk=message.pk).exists())

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_a_conversation_left_empty_is_deleted(self):
        emptied = self._old_session(messages=2)

        tasks.cleanup_old_reporting_messages()

        self.assertFalse(ReportingSession.objects.filter(pk=emptied.pk).exists())

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_an_old_conversation_with_a_recent_question_is_kept(self):
        session = self._old_session(messages=1)
        ReportingMessage.objects.create(session=session, prompt="recent")

        tasks.cleanup_old_reporting_messages()

        self.assertTrue(ReportingSession.objects.filter(pk=session.pk).exists())

    @override_constance_config(AI_REPORTING_MESSAGE_RETENTION_DAYS=90)
    def test_a_new_conversation_is_kept_before_its_first_question(self):
        """ask creates the conversation just before its first message."""
        session = ReportingSession.objects.create(user=self.user)

        tasks.cleanup_old_reporting_messages()

        self.assertTrue(ReportingSession.objects.filter(pk=session.pk).exists())
