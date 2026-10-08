"""Shared plumbing for the archive's management commands."""

from django.db import connection

OLD_TABLE_PREFIX = "old_proposal_"


def table_exists(name):
    with connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass(%s)", [name])
        return cursor.fetchone()[0] is not None


def detach_old_tables():
    """Drop every foreign key still held by the renamed ``old_proposal_*`` tables.

    ``ALTER TABLE ... RENAME`` preserves constraints, so after the
    reconciliation those tables are renamed but not detached: they still hold
    live foreign keys into ``permissions_role``, ``core_user``,
    ``structure_customer``, ``marketplace_offering`` and each other.

    That is not a tidiness problem. ``old_proposal_proposalprojectrolemapping``
    has a NOT NULL foreign key to ``permissions_role`` for eighteen rows, so
    deleting the fork's proposal roles fails outright until it is gone. And
    every one of the others is a trap set for some future deletion: a customer
    removed years from now would be blocked, or would cascade into what is
    supposed to be an immutable record.

    Returns the number of constraints dropped. Idempotent -- a second run finds
    nothing to do.
    """
    with connection.cursor() as cursor:
        # Dropping a foreign key locks the *referenced* table too, and
        # PostgreSQL refuses to ALTER a table with pending trigger events -- one
        # transaction that inserts into permissions_role and then detaches a
        # table referencing it dies with ObjectInUse. Firing the deferred checks
        # first empties that queue and is a no-op when it is already empty.
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cursor.execute(
            """
            SELECT c.conrelid::regclass::text, c.conname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'f'
              AND n.nspname = 'public'
              AND t.relname LIKE %s
            """,
            [OLD_TABLE_PREFIX + "%"],
        )
        constraints = cursor.fetchall()
        for table, name in constraints:
            cursor.execute(f'ALTER TABLE {table} DROP CONSTRAINT "{name}"')
    return len(constraints)


def unmanaged_references(table):
    """``[(referencing table, column, rows)]`` still pointing at ``table``.

    A last look before an irreversible delete, straight at PostgreSQL rather
    than the model graph: a table left over from a previous life holds foreign
    keys Django knows nothing about, and the only honest way to find them is to
    ask the database.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.conrelid::regclass::text, a.attname
            FROM pg_constraint c
            JOIN pg_attribute a
              ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
            WHERE c.contype = 'f' AND c.confrelid = to_regclass(%s)
            """,
            [table],
        )
        return cursor.fetchall()
