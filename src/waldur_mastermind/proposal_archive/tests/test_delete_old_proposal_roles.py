"""Deleting the fork's proposal roles is what unblocks the upstream replay.

It is also destructive in a way nothing else here is: a role's ``UserRole`` rows
cascade away with it, and they are the only record of who managed, co-led and
reviewed each proposal. So the command's most important behaviour is the one it
refuses to perform.
"""

from io import StringIO

from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase

from waldur_core.permissions import models as permission_models
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal_archive import models


class DeleteOldProposalRolesTest(TestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        self.proposal_ct, _ = ContentType.objects.get_or_create(
            app_label="proposal", model="proposal"
        )
        self.role = permission_models.Role.objects.create(
            name="PROPOSAL.MANAGER", is_system_role=True, content_type=self.proposal_ct
        )
        permission_models.UserRole.objects.create(
            user=self.user,
            role=self.role,
            content_type=self.proposal_ct,
            object_id=1,
        )

    def run_command(self, **kwargs):
        call_command("delete_old_proposal_roles", verbosity=0, **kwargs)

    def test_it_refuses_while_the_assignments_are_unarchived(self):
        with self.assertRaises(CommandError):
            self.run_command()
        self.assertTrue(permission_models.Role.objects.filter(pk=self.role.pk).exists())

    def test_it_proceeds_once_the_memberships_have_been_captured(self):
        models.ArchivedMembership.objects.create(
            scope_kind=models.ArchivedMembership.Scopes.PROPOSAL,
            role_name="PROPOSAL.MANAGER",
            user_uuid=self.user.uuid,
            user_username=self.user.username,
        )
        self.run_command()
        self.assertFalse(
            permission_models.Role.objects.filter(pk=self.role.pk).exists()
        )
        self.assertEqual(
            permission_models.UserRole.objects.filter(role=self.role).count(), 0
        )

    def test_force_overrides_the_refusal(self):
        self.run_command(force=True)
        self.assertFalse(
            permission_models.Role.objects.filter(pk=self.role.pk).exists()
        )

    def test_dry_run_deletes_nothing(self):
        self.run_command(dry_run=True, force=True)
        self.assertTrue(permission_models.Role.objects.filter(pk=self.role.pk).exists())

    def test_dry_run_counts_the_wider_cascade(self):
        """The assignments are not the whole of it -- invitations go too."""
        out = StringIO()
        call_command("delete_old_proposal_roles", dry_run=True, stdout=out)
        printed = out.getvalue()
        self.assertIn("permissions_userrole.role_id: would delete 1", printed)
        self.assertIn("nothing deleted", printed)
        self.assertTrue(permission_models.Role.objects.filter(pk=self.role.pk).exists())

    def test_roles_outside_the_proposal_app_are_left_alone(self):
        customer_ct = ContentType.objects.get(app_label="structure", model="customer")
        survivor = permission_models.Role.objects.create(
            name="CUSTOMER.OWNER_ARCHIVE_TEST",
            is_system_role=True,
            content_type=customer_ct,
        )
        self.run_command(force=True)
        self.assertTrue(permission_models.Role.objects.filter(pk=survivor.pk).exists())

    def test_a_second_run_is_a_no_op(self):
        self.run_command(force=True)
        self.run_command()


class MidMigrationDatabaseTest(TestCase):
    """The command runs on a database part-way through the resync.

    Some tables with a foreign key to Role are not there: the proposal app's own
    have been renamed to ``old_proposal_*`` by the reconciliation, and apps
    whose migrations have not been applied yet have none at all. Django's
    collector queries every one of them and dies on the first that is missing,
    having deleted nothing -- which is how the first production run failed, on
    ``waldur_sram_sramprojectrule``.
    """

    def setUp(self):
        self.proposal_ct, _ = ContentType.objects.get_or_create(
            app_label="proposal", model="proposal"
        )
        self.role = permission_models.Role.objects.create(
            name="PROPOSAL.MANAGER", is_system_role=True, content_type=self.proposal_ct
        )
        permission_models.UserRole.objects.create(
            user=structure_factories.UserFactory(),
            role=self.role,
            content_type=self.proposal_ct,
            object_id=1,
        )

    def test_a_missing_referencing_table_does_not_stop_the_delete(self):
        # DDL is transactional in PostgreSQL, so the test's own rollback puts
        # this back.
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE users_invitation CASCADE")
        call_command("delete_old_proposal_roles", verbosity=0, force=True)
        self.assertFalse(
            permission_models.Role.objects.filter(pk=self.role.pk).exists()
        )
        self.assertEqual(
            permission_models.UserRole.objects.filter(role_id=self.role.pk).count(), 0
        )

    def test_a_missing_column_does_not_stop_the_delete_either(self):
        """A table can predate the migration that added its role column."""
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE waldur_autoprovisioning_rule DROP COLUMN customer_role_id"
            )
        call_command("delete_old_proposal_roles", verbosity=0, force=True)
        self.assertFalse(
            permission_models.Role.objects.filter(pk=self.role.pk).exists()
        )

    def test_a_set_null_reference_is_cleared_rather_than_deleted(self):
        clone = permission_models.Role.objects.create(
            name="PROPOSAL.MANAGER.CLONE",
            content_type=ContentType.objects.get(
                app_label="structure", model="customer"
            ),
            template=self.role,
        )
        call_command("delete_old_proposal_roles", verbosity=0, force=True)
        clone.refresh_from_db()
        self.assertIsNone(clone.template_id)
