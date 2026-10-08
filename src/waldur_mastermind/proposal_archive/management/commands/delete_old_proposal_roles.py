"""Delete the fork's proposal roles, so upstream's replay can create its own.

``proposal.0001_squashed_0074`` -> ``0040_migrate_default_project_role`` does
``Role.objects.get(name="PROPOSAL.MANAGER", content_type=proposal_ct)`` and dies
with ``MultipleObjectsReturned`` when the fork's role is still there.  Roles live
in ``permissions_role``, which the reconciliation script does not touch, so on a
site that ran the fork's proposal app they survive and block the replay.

Deleting a role cascades its ``UserRole`` rows away, and those rows are the only
record of who managed, co-led and reviewed each proposal.  So this command
refuses to run until ``archive_old_proposals`` has captured them.
"""

from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.db.models import SET_NULL

from waldur_core.permissions import models as permission_models
from waldur_mastermind.proposal_archive import models, utils


class Command(BaseCommand):
    help = "Delete the fork's proposal-scoped roles ahead of the upstream replay."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be deleted, and delete nothing.",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help=(
                "Delete even though no memberships have been archived. Only for "
                "a site that never had any -- the assignments are not "
                "recoverable afterwards."
            ),
        )

    def handle(self, *args, **options):
        content_types = ContentType.objects.filter(app_label="proposal")
        if not content_types.exists():
            self.stdout.write("No proposal content types: nothing to delete.")
            return

        roles = permission_models.Role.objects.filter(content_type__in=content_types)
        if not roles.exists():
            self.stdout.write("No proposal-scoped roles: nothing to delete.")
            return

        assignments = permission_models.UserRole.objects.filter(role__in=roles)
        archived = models.ArchivedMembership.objects.count()

        self.stdout.write("Roles to delete:")
        for role in roles.order_by("name"):
            count = assignments.filter(role=role).count()
            system = "system" if role.is_system_role else "custom"
            self.stdout.write(
                f"  {role.name:<30} {role.content_type.model:<26} {system:<7} {count}"
            )
        total = assignments.count()
        self.stdout.write(f"\nAssignments that would be cascaded away: {total}")
        self.stdout.write(f"Memberships already archived:             {archived}")

        role_ids = list(roles.values_list("id", flat=True))

        if options["dry_run"]:
            # Counted, not guessed: the cascade reaches further than the
            # assignments -- invitations to these roles go too, and that number
            # is worth seeing before a production run rather than after.
            self.stdout.write("\nWhat the delete would touch:")
            self.clear_references(role_ids, dry_run=True)
            self.stdout.write(self.style.WARNING("\nDry run: nothing deleted."))
            return

        if total and not archived and not options["force"]:
            raise CommandError(
                "Refusing to delete: these roles carry assignments and the "
                "archive is empty. Run `waldur archive_old_proposals` first, or "
                "pass --force if losing them is intended."
            )

        with transaction.atomic():
            # The archived tables still hold foreign keys into permissions_role
            # unless the copy has already cut them loose. Eighteen of them are
            # NOT NULL, so the delete below fails outright without this.
            dropped = utils.detach_old_tables()
            if dropped:
                self.stdout.write(f"  dropped {dropped} foreign keys on old tables")
            self.clear_references(role_ids)
            self.check_nothing_still_points_at(role_ids)
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM permissions_role WHERE id = ANY(%s)", [role_ids]
                )
                deleted = cursor.rowcount
        # The manager caches roles by name; a stale entry would hand the replay
        # a deleted row.
        permission_models.Role.objects.clear_cache()
        self.stdout.write(self.style.SUCCESS(f"\nDeleted {deleted} roles."))

    def clear_references(self, role_ids, dry_run=False):
        """Detach everything pointing at these roles, in SQL rather than the ORM.

        ``queryset.delete()`` cannot be used here. Django's collector walks
        every model with a foreign key to ``Role`` and queries each one, and
        this command runs on a database part-way through the resync: the
        proposal app's own tables have been renamed to ``old_proposal_*``, and
        apps whose migrations have not been applied yet have no tables at all.
        The collector hits the first of those and dies with

            relation "waldur_sram_sramprojectrule" does not exist

        having deleted nothing. So the model graph decides the *policy* -- which
        is exactly what Django would have done, CASCADE or SET_NULL -- while
        PostgreSQL's own catalog decides what is really there.

        The table existing is not enough: a table can predate the migration that
        added its role column, which is how the second attempt failed --

            column "customer_role_id" does not exist

        on a ``waldur_autoprovisioning_rule`` that was there but older. Both are
        checked.
        """
        for relation in permission_models.Role._meta.related_objects:
            if relation.many_to_many:
                model = relation.through
                table = model._meta.db_table
                column = relation.field.m2m_reverse_name()
                on_delete = None
            else:
                table = relation.related_model._meta.db_table
                column = relation.field.column
                on_delete = relation.field.remote_field.on_delete

            with connection.cursor() as cursor:
                cursor.execute("SELECT to_regclass(%s)", [table])
                if cursor.fetchone()[0] is None:
                    self.stdout.write(f"  {table}.{column}: no such table, skipped")
                    continue
                cursor.execute(
                    """
                    SELECT 1 FROM pg_attribute
                    WHERE attrelid = to_regclass(%s) AND attname = %s
                      AND attnum > 0 AND NOT attisdropped
                    """,
                    [table, column],
                )
                if cursor.fetchone() is None:
                    self.stdout.write(f"  {table}.{column}: no such column, skipped")
                    continue

                clears = on_delete is SET_NULL
                if dry_run:
                    cursor.execute(
                        f'SELECT count(*) FROM "{table}" WHERE "{column}" = ANY(%s)',
                        [role_ids],
                    )
                    affected = cursor.fetchone()[0]
                    verb = "would clear" if clears else "would delete"
                elif clears:
                    cursor.execute(
                        f'UPDATE "{table}" SET "{column}" = NULL '
                        f'WHERE "{column}" = ANY(%s)',
                        [role_ids],
                    )
                    affected, verb = cursor.rowcount, "cleared"
                else:
                    cursor.execute(
                        f'DELETE FROM "{table}" WHERE "{column}" = ANY(%s)',
                        [role_ids],
                    )
                    affected, verb = cursor.rowcount, "deleted"
                if affected:
                    self.stdout.write(f"  {table}.{column}: {verb} {affected}")

    def check_nothing_still_points_at(self, role_ids):
        """Fail with an explanation rather than a raw constraint violation.

        ``clear_references`` works from Django's model graph, which cannot see a
        table left behind by an app this deployment no longer installs. Asking
        PostgreSQL directly is the only way to know, and a named table beats
        ``ForeignKeyViolation`` on a constraint nobody recognises.
        """
        blockers = []
        for table, column in utils.unmanaged_references("permissions_role"):
            with connection.cursor() as cursor:
                cursor.execute(
                    f'SELECT count(*) FROM "{table}" WHERE "{column}" = ANY(%s)',
                    [role_ids],
                )
                count = cursor.fetchone()[0]
            if count:
                blockers.append(f"{table}.{column} ({count} rows)")
        if blockers:
            raise CommandError(
                "Rows still reference these roles, so deleting them would "
                "violate a foreign key: " + ", ".join(blockers) + ". Nothing "
                "has been deleted."
            )
