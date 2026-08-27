import datetime

from django.test import TestCase

from waldur_core.structure.tests import fixtures as structure_fixtures
from waldur_openportal import models


def _dt(year, month, day, hour=0, minute=0):
    return datetime.datetime(
        year, month, day, hour, minute, tzinfo=datetime.timezone.utc
    )


def _make_managed_project(project=None, **kwargs):
    defaults = {
        "destination": "test-destination",
        "identifier": "test-identifier",
        "project": project,
    }
    defaults.update(kwargs)
    return models.ManagedProject.objects.create(**defaults)


def _record_event(managed_project, event_type, when):
    entry = models.ManagedProjectAuditEntry.objects.create(
        identifier=managed_project.identifier,
        destination=managed_project.destination,
        managed_project=managed_project,
        event_type=event_type,
    )
    models.ManagedProjectAuditEntry.objects.filter(pk=entry.pk).update(timestamp=when)
    return entry


def _set_created(managed_project, when):
    models.ManagedProject.objects.filter(pk=managed_project.pk).update(created=when)
    managed_project.refresh_from_db()


class SyncAttachmentTest(TestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project
        self.other_project = structure_fixtures.ProjectFixture().project
        self.managed_project = _make_managed_project()

    def test_attaching_creates_one_open_attachment(self):
        self.managed_project.project = self.project
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        attachments = self.managed_project.attachments.all()
        self.assertEqual(attachments.count(), 1)
        attachment = attachments.get()
        self.assertEqual(attachment.project, self.project)
        self.assertIsNone(attachment.detached_at)

    def test_calling_sync_twice_for_the_same_project_does_not_duplicate(self):
        self.managed_project.project = self.project
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()
        self.managed_project._sync_attachment()

        self.assertEqual(self.managed_project.attachments.count(), 1)

    def test_detaching_closes_the_open_attachment(self):
        self.managed_project.project = self.project
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        self.managed_project.project = None
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        attachments = self.managed_project.attachments.all()
        self.assertEqual(attachments.count(), 1)
        self.assertIsNotNone(attachments.get().detached_at)

    def test_moving_to_a_different_project_closes_old_and_opens_new(self):
        self.managed_project.project = self.project
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        self.managed_project.project = self.other_project
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        attachments = self.managed_project.attachments.order_by("attached_at")
        self.assertEqual(attachments.count(), 2)

        first, second = attachments
        self.assertEqual(first.project, self.project)
        self.assertIsNotNone(first.detached_at)
        self.assertEqual(second.project, self.other_project)
        self.assertIsNone(second.detached_at)

    def test_reattaching_after_a_detach_opens_a_new_row(self):
        self.managed_project.project = self.project
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        self.managed_project.project = None
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        self.managed_project.project = self.project
        self.managed_project.save(update_fields=["project"])
        self.managed_project._sync_attachment()

        attachments = self.managed_project.attachments.order_by("attached_at")
        self.assertEqual(attachments.count(), 2)
        self.assertIsNotNone(attachments[0].detached_at)
        self.assertIsNone(attachments[1].detached_at)


class GetAttachmentsTest(TestCase):
    def setUp(self):
        self.fixture = structure_fixtures.ProjectFixture()
        self.project = self.fixture.project

    def test_returns_existing_rows_without_reconstructing(self):
        managed_project = _make_managed_project(self.project)
        models.ManagedProjectAttachment.objects.create(
            managed_project=managed_project,
            project=self.project,
            attached_at=_dt(2026, 1, 1),
        )

        attachments = managed_project.get_attachments()

        self.assertEqual(attachments.count(), 1)
        self.assertEqual(attachments.get().note, "")

    def test_reconstructs_from_created_when_no_audit_trail(self):
        managed_project = _make_managed_project(self.project)
        _set_created(managed_project, _dt(2026, 1, 5))

        attachments = managed_project.get_attachments()

        self.assertEqual(attachments.count(), 1)
        attachment = attachments.get()
        self.assertEqual(attachment.attached_at, _dt(2026, 1, 5))
        self.assertIsNone(attachment.detached_at)
        self.assertIn("Reconstructed", attachment.note)

    def test_reconstructs_multiple_windows_from_audit_trail(self):
        managed_project = _make_managed_project(self.project)
        _record_event(
            managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 1, 1),
        )
        _record_event(
            managed_project,
            models.ManagedProjectAuditEventType.PROJECT_DETACHED,
            _dt(2026, 1, 10),
        )
        _record_event(
            managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 1, 20),
        )

        attachments = managed_project.get_attachments().order_by("attached_at")

        self.assertEqual(attachments.count(), 2)
        first, second = attachments
        self.assertEqual(first.attached_at, _dt(2026, 1, 1))
        self.assertEqual(first.detached_at, _dt(2026, 1, 10))
        self.assertEqual(second.attached_at, _dt(2026, 1, 20))
        self.assertIsNone(second.detached_at)

    def test_first_event_detach_uses_created_as_implicit_start(self):
        managed_project = _make_managed_project(self.project)
        _set_created(managed_project, _dt(2026, 1, 1))
        _record_event(
            managed_project,
            models.ManagedProjectAuditEventType.PROJECT_DETACHED,
            _dt(2026, 2, 1),
        )

        attachments = managed_project.get_attachments()

        self.assertEqual(attachments.count(), 1)
        attachment = attachments.get()
        self.assertEqual(attachment.attached_at, _dt(2026, 1, 1))
        self.assertEqual(attachment.detached_at, _dt(2026, 2, 1))

    def test_does_not_reconstruct_when_currently_unattached(self):
        managed_project = _make_managed_project(project=None)
        _record_event(
            managed_project,
            models.ManagedProjectAuditEventType.PROJECT_ATTACHED,
            _dt(2026, 1, 1),
        )
        _record_event(
            managed_project,
            models.ManagedProjectAuditEventType.PROJECT_DETACHED,
            _dt(2026, 1, 10),
        )

        attachments = managed_project.get_attachments()

        self.assertEqual(attachments.count(), 0)

    def test_is_idempotent(self):
        managed_project = _make_managed_project(self.project)
        _set_created(managed_project, _dt(2026, 1, 5))

        managed_project.get_attachments()
        second_call = managed_project.get_attachments()

        self.assertEqual(second_call.count(), 1)
