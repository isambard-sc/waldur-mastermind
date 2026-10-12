"""Copy the fork's proposal data into the archive.

The old tables have been renamed aside to ``old_proposal_*`` by
``scripts/resync_reconcile_db.sql``, and the Python models that described them
are gone, so everything here is raw SQL.  Nothing in this command imports
``waldur_mastermind.proposal``: it has to run while that app is absent from the
migration history, which is the whole point of the archive.

The copy is a **full refresh** -- it clears the archive and rebuilds it -- so it
can be re-run as often as it takes to get right.  See
``docs/guides/awards-site-upgrade-plan.md`` §4.
"""

import datetime
import decimal
import json
import uuid as uuid_module

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from waldur_mastermind.proposal_archive import models, utils

CALL_DOCUMENT_PREFIX = "call_documents/"
PROPOSAL_DOCUMENT_PREFIX = "proposal_project_supporting_documentation/"
ARCHIVED_CALL_DOCUMENT_PREFIX = "archived_call_documents/"
ARCHIVED_PROPOSAL_DOCUMENT_PREFIX = "archived_proposal_documentation/"


def jsonable(value):
    """Make a raw column value safe for a JSONField."""
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, uuid_module.UUID):
        return str(value)
    if isinstance(value, (bytes, memoryview)):
        return None
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


# Django installs a pass-through jsonb loader so that ``JSONField`` can do its
# own decoding, which means a raw cursor hands back the JSON *text*. Reading
# these tables without the ORM, we have to decode it ourselves -- otherwise a
# proposal's ``notes`` reach the archive as a string that looks like a list.
JSON_OIDS = {114, 3802}


def fetch(table, where=None, params=None):
    """Every column of ``table``, as a list of dicts."""
    sql = f'SELECT * FROM "{table}"'
    if where:
        sql += f" WHERE {where}"
    with connection.cursor() as cursor:
        cursor.execute(sql, params or [])
        columns = [c.name for c in cursor.description]
        json_columns = {c.name for c in cursor.description if c.type_code in JSON_OIDS}
        rows = []
        for row in cursor.fetchall():
            values = dict(zip(columns, row))
            for name in json_columns:
                if isinstance(values[name], str):
                    values[name] = json.loads(values[name])
            rows.append(values)
        return rows


def lookup(table, ids, columns):
    """``{pk: {column: value}}`` for the rows named by ``ids``.

    Reads live tables in bulk rather than per row: the awards site has 2,258
    proposals and a per-row query for each author would be 2,258 queries.
    """
    ids = {i for i in ids if i is not None}
    if not ids:
        return {}
    selected = ", ".join(f'"{c}"' for c in ("id", *columns))
    with connection.cursor() as cursor:
        cursor.execute(
            f'SELECT {selected} FROM "{table}" WHERE id = ANY(%s)', [list(ids)]
        )
        names = [c.name for c in cursor.description]
        return {row[0]: dict(zip(names, row)) for row in cursor.fetchall()}


# ``User.full_name`` is a property over first_name/last_name, not a column, so
# raw lookups have to select the parts and join them back.
USER_COLUMNS = ["uuid", "username", "first_name", "last_name"]


def person(row):
    """``(uuid, username, full_name)`` of a looked-up user row, or blanks."""
    if not row:
        return None, "", ""
    full_name = " ".join(
        part for part in (row.get("first_name"), row.get("last_name")) if part
    )
    return row.get("uuid"), row.get("username") or "", full_name


class Command(BaseCommand):
    help = "Copy the fork's old proposal tables into the read-only archive."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be copied, then roll back.",
        )
        parser.add_argument(
            "--skip-media",
            action="store_true",
            help=(
                "Leave media_file.name alone. Archived documents will 403 until "
                "the paths are moved; only useful for rehearsing the copy."
            ),
        )

    def handle(self, *args, **options):
        self.dry_run = options["dry_run"]
        if not utils.table_exists("old_proposal_call"):
            raise CommandError(
                "old_proposal_call does not exist. Run "
                "scripts/resync_reconcile_db.sql first -- it is what renames the "
                "fork's proposal tables aside."
            )

        self.counts = {}
        try:
            with transaction.atomic():
                self.wipe()
                calls = self.copy_calls()
                rounds = self.copy_rounds(calls)
                proposals = self.copy_proposals(calls, rounds)
                self.copy_requested_resources(proposals)
                self.copy_reviews(proposals)
                self.copy_documents(calls, proposals)
                self.copy_memberships(calls, proposals)
                if not options["skip_media"]:
                    self.move_media_paths()
                self.report(
                    "foreign keys dropped from old tables", utils.detach_old_tables()
                )
                if self.dry_run:
                    raise _Rollback
        except _Rollback:
            self.stdout.write(self.style.WARNING("\nDry run: rolled back."))

        self.stdout.write("")
        for label, count in self.counts.items():
            self.stdout.write(f"  {label:<28} {count}")

    def report(self, label, count):
        self.counts[label] = count
        self.stdout.write(f"{label}: {count}")

    def wipe(self):
        # ArchivedCall cascades to everything below it, but memberships scoped
        # to an organisation hang off no call, so they are cleared separately.
        models.ArchivedMembership.objects.all().delete()
        models.ArchivedCall.objects.all().delete()

    # -- calls ------------------------------------------------------------

    def copy_calls(self):
        """``{old call id: ArchivedCall}``."""
        rows = fetch("old_proposal_call")
        organisations = lookup(
            "old_proposal_callmanagingorganisation",
            [r.get("manager_id") for r in rows],
            ["uuid", "customer_id"],
        )
        customers = lookup(
            "structure_customer",
            [o.get("customer_id") for o in organisations.values()],
            ["uuid", "name"],
        )
        users = lookup(
            "core_user",
            [r.get("created_by_id") for r in rows],
            USER_COLUMNS,
        )

        result = {}
        for row in rows:
            organisation = organisations.get(row.get("manager_id")) or {}
            customer = customers.get(organisation.get("customer_id")) or {}
            author_uuid, author_username, author_name = person(
                users.get(row.get("created_by_id"))
            )
            result[row["id"]] = models.ArchivedCall.objects.create(
                uuid=row["uuid"],
                created=row["created"],
                modified=row["modified"],
                name=row.get("name") or "",
                slug=row.get("slug") or "",
                description=row.get("description") or "",
                state=row.get("state") or "",
                external_url=row.get("external_url"),
                reviewer_identity_visible_to_submitters=bool(
                    row.get("reviewer_identity_visible_to_submitters")
                ),
                reviews_visible_to_submitters=bool(
                    row.get("reviews_visible_to_submitters")
                ),
                fixed_duration_in_days=row.get("fixed_duration_in_days"),
                manager_uuid=organisation.get("uuid"),
                customer_uuid=customer.get("uuid"),
                customer_name=customer.get("name") or "",
                created_by_uuid=author_uuid,
                created_by_username=author_username,
                created_by_full_name=author_name,
                payload=jsonable(row),
            )
        self.report("calls", len(result))
        return result

    def copy_rounds(self, calls):
        rows = fetch("old_proposal_round")
        result = {}
        skipped = 0
        for row in rows:
            call = calls.get(row.get("call_id"))
            if call is None:
                skipped += 1
                continue
            result[row["id"]] = models.ArchivedRound.objects.create(
                uuid=row["uuid"],
                created=row["created"],
                modified=row["modified"],
                call=call,
                slug=row.get("slug") or "",
                start_time=row.get("start_time"),
                cutoff_time=row.get("cutoff_time"),
                review_strategy=row.get("review_strategy") or "",
                deciding_entity=row.get("deciding_entity") or "",
                allocation_time=row.get("allocation_time") or "",
                allocation_date=row.get("allocation_date"),
                review_duration_in_days=row.get("review_duration_in_days"),
                fixed_review_end_date=row.get("fixed_review_end_date"),
                minimum_number_of_reviewers=row.get("minimum_number_of_reviewers"),
                minimal_average_scoring=row.get("minimal_average_scoring"),
                minimum_required_uploads=row.get("minimum_required_uploads"),
                payload=jsonable(row),
            )
        self.report("rounds", len(result))
        if skipped:
            self.report("rounds without a call (skipped)", skipped)
        return result

    # -- proposals --------------------------------------------------------

    def copy_proposals(self, calls, rounds):
        rows = fetch("old_proposal_proposal")
        adjustments = self.adjustments_by_proposal()
        users = lookup(
            "core_user",
            [r.get("created_by_id") for r in rows]
            + [r.get("approved_by_id") for r in rows],
            USER_COLUMNS,
        )
        projects = lookup(
            "structure_project",
            [r.get("project_id") for r in rows],
            ["uuid", "name"],
        )

        result = {}
        skipped = 0
        for row in rows:
            round_ = rounds.get(row.get("round_id"))
            if round_ is None:
                skipped += 1
                continue
            project = projects.get(row.get("project_id")) or {}
            author_uuid, author_username, author_name = person(
                users.get(row.get("created_by_id"))
            )
            approver_uuid, approver_username, _ = person(
                users.get(row.get("approved_by_id"))
            )
            payload = jsonable(row)
            if row["id"] in adjustments:
                payload["resource_adjustments"] = adjustments[row["id"]]
            result[row["id"]] = models.ArchivedProposal.objects.create(
                uuid=row["uuid"],
                created=row["created"],
                modified=row["modified"],
                round=round_,
                call=round_.call,
                name=row.get("name") or "",
                slug=row.get("slug") or "",
                description=row.get("description") or "",
                state=row.get("state") or "",
                duration_in_days=row.get("duration_in_days"),
                project_summary=row.get("project_summary") or "",
                project_duration=row.get("project_duration"),
                project_is_confidential=bool(row.get("project_is_confidential")),
                project_has_civilian_purpose=bool(
                    row.get("project_has_civilian_purpose")
                ),
                oecd_fos_2007_code=row.get("oecd_fos_2007_code") or "",
                allocation_comment=row.get("allocation_comment"),
                submitted_at=row.get("submitted_at"),
                notes=jsonable(row.get("notes") or []),
                project_uuid=project.get("uuid"),
                project_name=project.get("name") or "",
                created_by_uuid=author_uuid,
                created_by_username=author_username,
                created_by_full_name=author_name,
                approved_by_uuid=approver_uuid,
                approved_by_username=approver_username,
                payload=payload,
            )
        self.report("proposals", len(result))
        if skipped:
            self.report("proposals without a round (skipped)", skipped)
        return result

    def adjustments_by_proposal(self):
        """``ProposalResourceAdjustment`` rows, folded into the proposal payload.

        223 rows of "the call manager changed this request before allocating",
        interesting as a record but not worth a model of their own.
        """
        if not utils.table_exists("old_proposal_proposalresourceadjustment"):
            return {}
        grouped = {}
        for row in fetch("old_proposal_proposalresourceadjustment"):
            grouped.setdefault(row.get("proposal_id"), []).append(jsonable(row))
        return grouped

    def copy_requested_resources(self, proposals):
        rows = fetch("old_proposal_requestedresource")
        offerings_by_request = lookup(
            "old_proposal_requestedoffering",
            [r.get("requested_offering_id") for r in rows],
            ["offering_id", "plan_id"],
        )
        templates = lookup(
            "old_proposal_callresourcetemplate",
            [r.get("call_resource_template_id") for r in rows],
            ["name"],
        )
        offerings = lookup(
            "marketplace_offering",
            [o.get("offering_id") for o in offerings_by_request.values()],
            ["uuid", "name"],
        )
        plans = lookup(
            "marketplace_plan",
            [o.get("plan_id") for o in offerings_by_request.values()],
            ["uuid", "name"],
        )
        resources = lookup(
            "marketplace_resource", [r.get("resource_id") for r in rows], ["uuid"]
        )
        users = lookup(
            "core_user",
            [r.get("created_by_id") for r in rows],
            USER_COLUMNS,
        )

        created = 0
        skipped = 0
        for row in rows:
            proposal = proposals.get(row.get("proposal_id"))
            if proposal is None:
                skipped += 1
                continue
            requested = offerings_by_request.get(row.get("requested_offering_id")) or {}
            offering = offerings.get(requested.get("offering_id")) or {}
            plan = plans.get(requested.get("plan_id")) or {}
            template = templates.get(row.get("call_resource_template_id")) or {}
            resource = resources.get(row.get("resource_id")) or {}
            author_uuid, author_username, _ = person(
                users.get(row.get("created_by_id"))
            )
            models.ArchivedRequestedResource.objects.create(
                uuid=row["uuid"],
                created=row["created"],
                modified=row["modified"],
                proposal=proposal,
                offering_uuid=offering.get("uuid"),
                offering_name=offering.get("name") or "",
                plan_uuid=plan.get("uuid"),
                plan_name=plan.get("name") or "",
                template_name=template.get("name") or "",
                attributes=jsonable(row.get("attributes") or {}),
                limits=jsonable(row.get("limits") or {}),
                resource_uuid=resource.get("uuid"),
                created_by_uuid=author_uuid,
                created_by_username=author_username,
                payload=jsonable(row),
            )
            created += 1
        self.report("requested resources", created)
        if skipped:
            self.report("requested resources orphaned (skipped)", skipped)

    def copy_reviews(self, proposals):
        rows = fetch("old_proposal_review")
        users = lookup(
            "core_user",
            [r.get("reviewer_id") for r in rows],
            USER_COLUMNS,
        )
        comments = {}
        if utils.table_exists("old_proposal_reviewcomment"):
            for comment in fetch("old_proposal_reviewcomment"):
                comments.setdefault(comment.get("review_id"), []).append(
                    jsonable(comment)
                )

        created = 0
        skipped = 0
        comment_fields = [
            f.name
            for f in models.ArchivedReview._meta.get_fields()
            if f.name.startswith("comment_")
        ]
        for row in rows:
            proposal = proposals.get(row.get("proposal_id"))
            if proposal is None:
                skipped += 1
                continue
            reviewer_uuid, reviewer_username, reviewer_name = person(
                users.get(row.get("reviewer_id"))
            )
            models.ArchivedReview.objects.create(
                uuid=row["uuid"],
                created=row["created"],
                modified=row["modified"],
                proposal=proposal,
                state=row.get("state") or "",
                summary_score=row.get("summary_score") or 0,
                summary_public_comment=row.get("summary_public_comment") or "",
                summary_private_comment=row.get("summary_private_comment") or "",
                reviewer_uuid=reviewer_uuid,
                reviewer_username=reviewer_username,
                reviewer_full_name=reviewer_name,
                comments=comments.get(row["id"], []),
                payload=jsonable(row),
                **{name: row.get(name) for name in comment_fields},
            )
            created += 1
        self.report("reviews", created)
        if skipped:
            self.report("reviews orphaned (skipped)", skipped)

    # -- documents --------------------------------------------------------

    def copy_documents(self, calls, proposals):
        created = 0
        skipped = 0
        for row in fetch("old_proposal_calldocument"):
            call = calls.get(row.get("call_id"))
            if call is None:
                skipped += 1
                continue
            models.ArchivedCallDocument.objects.create(
                uuid=row["uuid"],
                created=row["created"],
                modified=row["modified"],
                call=call,
                description=row.get("description") or "",
                file=self.rename(
                    row.get("file"), CALL_DOCUMENT_PREFIX, ARCHIVED_CALL_DOCUMENT_PREFIX
                ),
                payload=jsonable(row),
            )
            created += 1
        self.report("call documents", created)
        if skipped:
            self.report("call documents orphaned (skipped)", skipped)

        created = 0
        skipped = 0
        for row in fetch("old_proposal_proposaldocumentation"):
            proposal = proposals.get(row.get("proposal_id"))
            if proposal is None:
                skipped += 1
                continue
            models.ArchivedProposalDocument.objects.create(
                uuid=row["uuid"],
                created=row["created"],
                modified=row["modified"],
                proposal=proposal,
                file=self.rename(
                    row.get("file"),
                    PROPOSAL_DOCUMENT_PREFIX,
                    ARCHIVED_PROPOSAL_DOCUMENT_PREFIX,
                ),
                payload=jsonable(row),
            )
            created += 1
        self.report("proposal documents", created)
        if skipped:
            self.report("proposal documents orphaned (skipped)", skipped)

    @staticmethod
    def rename(path, old_prefix, new_prefix):
        """The archive's path for a stored file.

        A path that is already under the new prefix is left alone, so the copy
        stays re-runnable after the media rows have been moved.
        """
        if not path:
            return ""
        if path.startswith(new_prefix):
            return path
        if path.startswith(old_prefix):
            return new_prefix + path[len(old_prefix) :]
        return path

    def move_media_paths(self):
        """Point ``media_file.name`` at the archive's prefixes.

        The bytes stay where they are -- this renames rows, not files.  It has
        to happen because upstream's proposal app registers the old prefixes
        for itself, and its rule queries its own (now empty) tables: leave the
        paths alone and every archived document 403s.
        """
        moved = 0
        with connection.cursor() as cursor:
            for old_prefix, new_prefix in (
                (CALL_DOCUMENT_PREFIX, ARCHIVED_CALL_DOCUMENT_PREFIX),
                (PROPOSAL_DOCUMENT_PREFIX, ARCHIVED_PROPOSAL_DOCUMENT_PREFIX),
            ):
                cursor.execute(
                    "UPDATE media_file SET name = %s || substring(name from %s) "
                    "WHERE name LIKE %s",
                    [new_prefix, len(old_prefix) + 1, old_prefix + "%"],
                )
                moved += cursor.rowcount
        self.report("media paths moved", moved)

    # -- memberships ------------------------------------------------------

    def copy_memberships(self, calls, proposals):
        """Capture the role assignments before the roles themselves are deleted.

        ``UserRole`` scopes through a generic foreign key, so these rows now
        point at object ids that live only in ``old_proposal_*``.  Rows whose
        ``object_id`` resolves to nothing are counted, not archived: a reference
        to a proposal that exists nowhere is a number, not a record.
        """
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, model FROM django_content_type WHERE app_label = 'proposal'"
            )
            content_types = {row[1]: row[0] for row in cursor.fetchall()}
        if not content_types:
            self.report("memberships", 0)
            return

        wanted = {
            "call": models.ArchivedMembership.Scopes.CALL,
            "proposal": models.ArchivedMembership.Scopes.PROPOSAL,
            "callmanagingorganisation": models.ArchivedMembership.Scopes.ORGANISATION,
        }
        ids = [content_types[m] for m in wanted if m in content_types]
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT ur.uuid, ur.created, ur.modified, ur.object_id,
                       ct.model, r.name, r.description,
                       u.uuid, u.username, u.first_name, u.last_name,
                       ur.is_active, ur.expiration_time, ur.revoke_reason,
                       cb.username, rb.username
                FROM permissions_userrole ur
                JOIN django_content_type ct ON ct.id = ur.content_type_id
                JOIN permissions_role r ON r.id = ur.role_id
                JOIN core_user u ON u.id = ur.user_id
                LEFT JOIN core_user cb ON cb.id = ur.created_by_id
                LEFT JOIN core_user rb ON rb.id = ur.revoked_by_id
                WHERE ur.content_type_id = ANY(%s)
                """,
                [ids],
            )
            rows = cursor.fetchall()

        organisations = lookup(
            "old_proposal_callmanagingorganisation",
            [r[3] for r in rows if r[4] == "callmanagingorganisation"],
            ["customer_id"],
        )
        customers = lookup(
            "structure_customer",
            [o.get("customer_id") for o in organisations.values()],
            ["uuid", "name"],
        )

        batch = []
        orphans = {}
        for row in rows:
            (
                row_uuid,
                created,
                modified,
                object_id,
                model,
                role_name,
                role_description,
                user_uuid,
                username,
                first_name,
                last_name,
                is_active,
                expiration_time,
                revoke_reason,
                granted_by,
                revoked_by,
            ) = row
            full_name = " ".join(part for part in (first_name, last_name) if part)
            call = proposal = None
            organisation_uuid = organisation_name = None
            if model == "call":
                call = calls.get(object_id)
                if call is None:
                    orphans[model] = orphans.get(model, 0) + 1
                    continue
            elif model == "proposal":
                proposal = proposals.get(object_id)
                if proposal is None:
                    orphans[model] = orphans.get(model, 0) + 1
                    continue
                call = proposal.call
            else:
                organisation = organisations.get(object_id) or {}
                customer = customers.get(organisation.get("customer_id")) or {}
                if not customer:
                    orphans[model] = orphans.get(model, 0) + 1
                    continue
                organisation_uuid = customer.get("uuid")
                organisation_name = customer.get("name")

            batch.append(
                models.ArchivedMembership(
                    uuid=row_uuid,
                    created=created,
                    modified=modified,
                    scope_kind=wanted[model],
                    call=call,
                    proposal=proposal,
                    organisation_customer_uuid=organisation_uuid,
                    organisation_customer_name=organisation_name or "",
                    role_name=role_name,
                    role_description=role_description or "",
                    user_uuid=user_uuid,
                    user_username=username or "",
                    user_full_name=full_name or "",
                    is_active=is_active,
                    expiration_time=expiration_time,
                    granted_by_username=granted_by or "",
                    revoked_by_username=revoked_by or "",
                    revoke_reason=revoke_reason or "",
                )
            )
        models.ArchivedMembership.objects.bulk_create(batch, batch_size=1000)
        self.report("memberships", len(batch))
        for model, count in sorted(orphans.items()):
            self.report(f"memberships on a missing {model} (skipped)", count)


class _Rollback(Exception):
    """Unwinds the copy's transaction at the end of a dry run."""
