"""The renamed tables are supposed to be inert. Renaming does not make them so.

``ALTER TABLE ... RENAME`` preserves constraints, so after
``resync_reconcile_db.sql`` the ``old_proposal_*`` tables still hold live
foreign keys into ``permissions_role``, ``core_user``, ``structure_customer``
and each other. One of them -- ``proposalprojectrolemapping.proposal_role_id``,
NOT NULL -- blocks the role deletion outright. The rest are traps for some
future deletion of a user or a customer.
"""

from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase

from waldur_core.permissions import models as permission_models
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal_archive import utils

from .test_archive_old_proposals import OldProposalData


class DetachOldTablesTest(TestCase):
    def setUp(self):
        self.proposal_ct, _ = ContentType.objects.get_or_create(
            app_label="proposal", model="proposal"
        )
        self.role = permission_models.Role.objects.create(
            name="PROPOSAL.MANAGER", is_system_role=True, content_type=self.proposal_ct
        )
        self.user = structure_factories.UserFactory()
        # What the rename leaves behind: an archived table whose NOT NULL
        # foreign key still points into a live one.
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE old_proposal_proposalprojectrolemapping (
                    id serial PRIMARY KEY,
                    uuid uuid NOT NULL,
                    proposal_role_id integer NOT NULL
                        REFERENCES permissions_role (id),
                    created_by_id integer REFERENCES core_user (id)
                )
                """
            )
            cursor.execute(
                "INSERT INTO old_proposal_proposalprojectrolemapping "
                "(uuid, proposal_role_id, created_by_id) "
                "VALUES (gen_random_uuid(), %s, %s)",
                [self.role.id, self.user.id],
            )

    def constraint_count(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM pg_constraint "
                "WHERE contype = 'f' "
                "AND conrelid = to_regclass("
                "'old_proposal_proposalprojectrolemapping')"
            )
            return cursor.fetchone()[0]

    def test_a_renamed_table_still_holds_its_foreign_keys(self):
        self.assertEqual(self.constraint_count(), 2)

    def test_detaching_drops_them(self):
        self.assertEqual(utils.detach_old_tables(), 2)
        self.assertEqual(self.constraint_count(), 0)

    def test_detaching_twice_is_a_no_op(self):
        utils.detach_old_tables()
        self.assertEqual(utils.detach_old_tables(), 0)

    def test_the_archived_rows_survive_it(self):
        utils.detach_old_tables()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM old_proposal_proposalprojectrolemapping"
            )
            self.assertEqual(cursor.fetchone()[0], 1)

    def test_the_role_delete_gets_through(self):
        call_command("delete_old_proposal_roles", verbosity=0, force=True)
        self.assertFalse(
            permission_models.Role.objects.filter(pk=self.role.pk).exists()
        )

    def test_an_unmanaged_reference_is_named_rather_than_left_to_the_database(self):
        """A table Django cannot see must not surface as a raw constraint error."""
        # Detaching is what the command does first, so to see the guard fire the
        # table has to be one detach_old_tables() does not cover.
        with connection.cursor() as cursor:
            cursor.execute(
                "ALTER TABLE old_proposal_proposalprojectrolemapping "
                "RENAME TO legacy_proposalprojectrolemapping"
            )
        with self.assertRaises(CommandError) as caught:
            call_command("delete_old_proposal_roles", verbosity=0, force=True)
        self.assertIn("legacy_proposalprojectrolemapping", str(caught.exception))
        self.assertTrue(permission_models.Role.objects.filter(pk=self.role.pk).exists())


class CopyDetachesTest(OldProposalData, TestCase):
    """The copy is where the detaching belongs: it owns the old tables."""

    def setUp(self):
        super().setUp()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE old_proposal_proposalprojectrolemapping (
                    id serial PRIMARY KEY,
                    uuid uuid NOT NULL,
                    created_by_id integer REFERENCES core_user (id)
                )
                """
            )

    def test_the_copy_cuts_the_old_tables_loose(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM pg_constraint WHERE contype = 'f' "
                "AND conrelid = to_regclass("
                "'old_proposal_proposalprojectrolemapping')"
            )
            self.assertEqual(cursor.fetchone()[0], 1)
        call_command("archive_old_proposals", verbosity=0)
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM pg_constraint WHERE contype = 'f' "
                "AND conrelid = to_regclass("
                "'old_proposal_proposalprojectrolemapping')"
            )
            self.assertEqual(cursor.fetchone()[0], 0)
