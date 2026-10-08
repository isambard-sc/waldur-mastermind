"""The copy runs against tables no model describes any more.

The fork's proposal app is gone from the codebase, so these tests build a
miniature ``old_proposal_*`` schema by hand -- only the columns the copy reads,
plus a couple it does not, to prove they land in the payload.  That is the same
position the command is in on the awards site: raw SQL against tables the ORM
knows nothing about.
"""

import uuid

from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import connection
from django.test import TestCase
from django.utils import timezone

from waldur_core.permissions import models as permission_models
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal_archive import models

NOW = timezone.now()

OLD_SCHEMA = """
CREATE TABLE old_proposal_callmanagingorganisation (
    id serial PRIMARY KEY, uuid uuid NOT NULL, customer_id integer,
    created timestamptz, modified timestamptz, description text
);
CREATE TABLE old_proposal_call (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, name varchar(150), slug varchar(50),
    description text, state varchar(10), external_url varchar(200),
    reviewer_identity_visible_to_submitters boolean,
    reviews_visible_to_submitters boolean, fixed_duration_in_days integer,
    manager_id integer, created_by_id integer, backend_id varchar(255)
);
CREATE TABLE old_proposal_round (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, slug varchar(50), call_id integer,
    start_time timestamptz, cutoff_time timestamptz,
    review_strategy varchar(20), deciding_entity varchar(20),
    allocation_time varchar(20), allocation_date timestamptz,
    review_duration_in_days integer, fixed_review_end_date timestamptz,
    minimum_number_of_reviewers integer, minimal_average_scoring numeric(6,2),
    minimum_required_uploads integer
);
CREATE TABLE old_proposal_proposal (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, name varchar(150), slug varchar(50),
    description text, state varchar(10), round_id integer,
    project_id integer, duration_in_days integer, approved_by_id integer,
    created_by_id integer, project_summary text, project_duration integer,
    project_is_confidential boolean, project_has_civilian_purpose boolean,
    allocation_comment varchar(150), submitted_at timestamptz,
    stale_reminder_sent_at timestamptz, notes jsonb,
    oecd_fos_2007_code varchar(80)
);
CREATE TABLE old_proposal_requestedoffering (
    id serial PRIMARY KEY, uuid uuid NOT NULL, call_id integer,
    offering_id integer, plan_id integer, state varchar(20)
);
CREATE TABLE old_proposal_callresourcetemplate (
    id serial PRIMARY KEY, uuid uuid NOT NULL, name varchar(255),
    call_id integer, requested_offering_id integer
);
CREATE TABLE old_proposal_requestedresource (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, proposal_id integer, requested_offering_id integer,
    call_resource_template_id integer, attributes jsonb, limits jsonb,
    resource_id integer, created_by_id integer
);
CREATE TABLE old_proposal_review (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, proposal_id integer, state varchar(10),
    summary_score smallint, summary_public_comment text,
    summary_private_comment text, reviewer_id integer,
    comment_project_title varchar(255), comment_project_summary varchar(255),
    comment_project_description varchar(255),
    comment_project_duration varchar(255),
    comment_project_is_confidential varchar(255),
    comment_project_has_civilian_purpose varchar(255),
    comment_project_supporting_documentation varchar(255),
    comment_resource_requests varchar(255), comment_team varchar(255)
);
CREATE TABLE old_proposal_reviewcomment (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, review_id integer, message varchar(255)
);
CREATE TABLE old_proposal_calldocument (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, call_id integer, file varchar(100), description text
);
CREATE TABLE old_proposal_proposaldocumentation (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, proposal_id integer, file varchar(100)
);
CREATE TABLE old_proposal_proposalresourceadjustment (
    id serial PRIMARY KEY, uuid uuid NOT NULL, created timestamptz,
    modified timestamptz, proposal_id integer, action varchar(20),
    comment text
);
"""


def sql(statement, params=None):
    with connection.cursor() as cursor:
        cursor.execute(statement, params)
        if cursor.description:
            return cursor.fetchone()


class OldProposalData:
    """Builds the miniature old schema and one call/round/proposal in it."""

    def setUp(self):
        with connection.cursor() as cursor:
            cursor.execute(OLD_SCHEMA)

        self.customer = structure_factories.CustomerFactory()
        self.project = structure_factories.ProjectFactory(customer=self.customer)
        self.author = structure_factories.UserFactory(
            username="applicant", full_name="An Applicant"
        )
        self.reviewer = structure_factories.UserFactory(
            username="reviewer", full_name="A Reviewer"
        )

        self.organisation_uuid = uuid.uuid4()
        self.organisation_id = sql(
            "INSERT INTO old_proposal_callmanagingorganisation "
            "(uuid, customer_id, created, modified) VALUES (%s, %s, %s, %s) "
            "RETURNING id",
            [self.organisation_uuid, self.customer.id, NOW, NOW],
        )[0]

        self.call_uuid = uuid.uuid4()
        self.call_id = sql(
            "INSERT INTO old_proposal_call (uuid, created, modified, name, slug, "
            "description, state, manager_id, created_by_id, "
            "reviewer_identity_visible_to_submitters, reviews_visible_to_submitters, "
            "backend_id) "
            "VALUES (%s, %s, %s, 'Pilot call', 'pilot-call', 'A call', 'archived', "
            "%s, %s, false, true, 'legacy-42') RETURNING id",
            [self.call_uuid, NOW, NOW, self.organisation_id, self.author.id],
        )[0]

        self.round_uuid = uuid.uuid4()
        self.round_id = sql(
            "INSERT INTO old_proposal_round (uuid, created, modified, slug, call_id, "
            "start_time, cutoff_time, minimal_average_scoring) "
            "VALUES (%s, %s, %s, 'round-1', %s, %s, %s, 4.50) RETURNING id",
            [self.round_uuid, NOW, NOW, self.call_id, NOW, NOW],
        )[0]

        self.proposal_uuid = uuid.uuid4()
        self.proposal_id = sql(
            "INSERT INTO old_proposal_proposal (uuid, created, modified, name, slug, "
            "state, round_id, project_id, created_by_id, project_summary, "
            "project_is_confidential, project_has_civilian_purpose, submitted_at, "
            "notes) "
            "VALUES (%s, %s, %s, 'A proposal', 'a-proposal', 'accepted', %s, %s, %s, "
            "'Summary', true, true, %s, %s) RETURNING id",
            [
                self.proposal_uuid,
                NOW,
                NOW,
                self.round_id,
                self.project.id,
                self.author.id,
                NOW,
                '[{"timestamp": "2026-01-01T00:00:00Z", "text": "noted"}]',
            ],
        )[0]

    def copy(self, **kwargs):
        call_command("archive_old_proposals", verbosity=0, **kwargs)


class ArchiveCopyTest(OldProposalData, TestCase):
    def test_call_is_copied_with_its_organisation_flattened_onto_it(self):
        self.copy()
        call = models.ArchivedCall.objects.get()
        self.assertEqual(call.uuid, self.call_uuid)
        self.assertEqual(call.name, "Pilot call")
        self.assertEqual(call.customer_uuid, self.customer.uuid)
        self.assertEqual(call.customer_name, self.customer.name)
        self.assertEqual(call.manager_uuid, self.organisation_uuid)
        self.assertEqual(call.created_by_username, "applicant")

    def test_original_timestamps_survive_the_copy(self):
        self.copy()
        call = models.ArchivedCall.objects.get()
        self.assertEqual(call.created, NOW)
        self.assertEqual(call.modified, NOW)

    def test_columns_with_no_field_of_their_own_land_in_the_payload(self):
        self.copy()
        call = models.ArchivedCall.objects.get()
        self.assertEqual(call.payload["backend_id"], "legacy-42")

    def test_proposal_carries_its_call_as_well_as_its_round(self):
        self.copy()
        proposal = models.ArchivedProposal.objects.get()
        self.assertEqual(proposal.round.uuid, self.round_uuid)
        self.assertEqual(proposal.call.uuid, self.call_uuid)
        self.assertEqual(proposal.project_uuid, self.project.uuid)
        self.assertEqual(proposal.notes[0]["text"], "noted")
        self.assertTrue(proposal.project_is_confidential)

    def test_text_longer_than_the_live_model_allowed_is_copied_whole(self):
        """The live models cap a description at 2,000 characters. Production
        proposals exceed it, and the first real run of the copy died on exactly
        that. An archive that truncates -- or refuses -- is not an archive."""
        long_text = "x" * 8000
        sql(
            "UPDATE old_proposal_proposal SET description = %s WHERE id = %s",
            [long_text, self.proposal_id],
        )
        self.copy()
        self.assertEqual(models.ArchivedProposal.objects.get().description, long_text)

    def test_resource_adjustments_are_folded_into_the_proposal_payload(self):
        sql(
            "INSERT INTO old_proposal_proposalresourceadjustment "
            "(uuid, created, modified, proposal_id, action, comment) "
            "VALUES (%s, %s, %s, %s, 'reduce', 'trimmed')",
            [uuid.uuid4(), NOW, NOW, self.proposal_id],
        )
        self.copy()
        proposal = models.ArchivedProposal.objects.get()
        self.assertEqual(len(proposal.payload["resource_adjustments"]), 1)
        self.assertEqual(
            proposal.payload["resource_adjustments"][0]["comment"], "trimmed"
        )

    def test_review_keeps_its_field_comments_and_reviewer(self):
        review_uuid = uuid.uuid4()
        sql(
            "INSERT INTO old_proposal_review (uuid, created, modified, proposal_id, "
            "state, summary_score, summary_private_comment, reviewer_id, "
            "comment_team) VALUES (%s, %s, %s, %s, 'submitted', 7, 'candid', %s, "
            "'strong team')",
            [review_uuid, NOW, NOW, self.proposal_id, self.reviewer.id],
        )
        self.copy()
        review = models.ArchivedReview.objects.get()
        self.assertEqual(review.uuid, review_uuid)
        self.assertEqual(review.summary_score, 7)
        self.assertEqual(review.summary_private_comment, "candid")
        self.assertEqual(review.comment_team, "strong team")
        self.assertEqual(review.reviewer_username, "reviewer")

    def test_review_comments_are_folded_into_the_review(self):
        review_id = sql(
            "INSERT INTO old_proposal_review (uuid, created, modified, proposal_id, "
            "state, summary_score) VALUES (%s, %s, %s, %s, 'submitted', 1) "
            "RETURNING id",
            [uuid.uuid4(), NOW, NOW, self.proposal_id],
        )[0]
        sql(
            "INSERT INTO old_proposal_reviewcomment (uuid, created, modified, "
            "review_id, message) VALUES (%s, %s, %s, %s, 'please clarify')",
            [uuid.uuid4(), NOW, NOW, review_id],
        )
        self.copy()
        review = models.ArchivedReview.objects.get()
        self.assertEqual(review.comments[0]["message"], "please clarify")

    def test_rows_orphaned_by_an_earlier_deletion_are_skipped_not_crashed_on(self):
        sql(
            "INSERT INTO old_proposal_review (uuid, created, modified, proposal_id, "
            "state, summary_score) VALUES (%s, %s, %s, 9999, 'submitted', 1)",
            [uuid.uuid4(), NOW, NOW],
        )
        self.copy()
        self.assertEqual(models.ArchivedReview.objects.count(), 0)
        self.assertEqual(models.ArchivedProposal.objects.count(), 1)

    def test_copy_is_a_full_refresh_so_it_can_be_re_run(self):
        self.copy()
        self.copy()
        self.assertEqual(models.ArchivedCall.objects.count(), 1)
        self.assertEqual(models.ArchivedProposal.objects.count(), 1)

    def test_dry_run_writes_nothing(self):
        self.copy(dry_run=True)
        self.assertEqual(models.ArchivedCall.objects.count(), 0)

    def test_requested_resource_flattens_offering_plan_and_template(self):
        from waldur_mastermind.marketplace.tests import (
            factories as marketplace_factories,
        )

        offering = marketplace_factories.OfferingFactory()
        plan = marketplace_factories.PlanFactory(offering=offering)
        requested_offering_id = sql(
            "INSERT INTO old_proposal_requestedoffering (uuid, call_id, offering_id, "
            "plan_id, state) VALUES (%s, %s, %s, %s, 'accepted') RETURNING id",
            [uuid.uuid4(), self.call_id, offering.id, plan.id],
        )[0]
        template_id = sql(
            "INSERT INTO old_proposal_callresourcetemplate (uuid, name, call_id, "
            "requested_offering_id) VALUES (%s, 'Small', %s, %s) RETURNING id",
            [uuid.uuid4(), self.call_id, requested_offering_id],
        )[0]
        sql(
            "INSERT INTO old_proposal_requestedresource (uuid, created, modified, "
            "proposal_id, requested_offering_id, call_resource_template_id, "
            "attributes, limits) VALUES (%s, %s, %s, %s, %s, %s, '{}', "
            "'{\"cpu\": 4}')",
            [
                uuid.uuid4(),
                NOW,
                NOW,
                self.proposal_id,
                requested_offering_id,
                template_id,
            ],
        )
        self.copy()
        resource = models.ArchivedRequestedResource.objects.get()
        self.assertEqual(resource.offering_uuid, offering.uuid)
        self.assertEqual(resource.plan_uuid, plan.uuid)
        self.assertEqual(resource.template_name, "Small")
        self.assertEqual(resource.limits, {"cpu": 4})


class DocumentPrefixTest(OldProposalData, TestCase):
    """The documents have to leave the live app's media prefixes behind."""

    def setUp(self):
        super().setUp()
        sql(
            "INSERT INTO old_proposal_calldocument (uuid, created, modified, "
            "call_id, file) VALUES (%s, %s, %s, %s, 'call_documents/terms.pdf')",
            [uuid.uuid4(), NOW, NOW, self.call_id],
        )
        sql(
            "INSERT INTO old_proposal_proposaldocumentation (uuid, created, "
            "modified, proposal_id, file) VALUES (%s, %s, %s, %s, "
            "'proposal_project_supporting_documentation/cv.pdf')",
            [uuid.uuid4(), NOW, NOW, self.proposal_id],
        )
        for name in (
            "call_documents/terms.pdf",
            "proposal_project_supporting_documentation/cv.pdf",
        ):
            sql(
                "INSERT INTO media_file (uuid, created, modified, name, content, "
                "size, mime_type, hash) VALUES (%s, %s, %s, %s, %s, 3, "
                "'application/pdf', 'x')",
                [uuid.uuid4(), NOW, NOW, name, b"pdf"],
            )

    def stored_names(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT name FROM media_file ORDER BY name")
            return [row[0] for row in cursor.fetchall()]

    def test_document_paths_move_onto_the_archive_prefixes(self):
        self.copy()
        self.assertEqual(
            models.ArchivedCallDocument.objects.get().file.name,
            "archived_call_documents/terms.pdf",
        )
        self.assertEqual(
            models.ArchivedProposalDocument.objects.get().file.name,
            "archived_proposal_documentation/cv.pdf",
        )

    def test_the_stored_media_rows_move_with_them(self):
        self.copy()
        self.assertEqual(
            self.stored_names(),
            [
                "archived_call_documents/terms.pdf",
                "archived_proposal_documentation/cv.pdf",
            ],
        )

    def test_moving_the_paths_twice_does_not_move_them_twice(self):
        self.copy()
        self.copy()
        self.assertEqual(
            self.stored_names(),
            [
                "archived_call_documents/terms.pdf",
                "archived_proposal_documentation/cv.pdf",
            ],
        )

    def test_skip_media_leaves_the_stored_rows_alone(self):
        self.copy(skip_media=True)
        self.assertEqual(
            self.stored_names(),
            [
                "call_documents/terms.pdf",
                "proposal_project_supporting_documentation/cv.pdf",
            ],
        )


class MembershipCaptureTest(OldProposalData, TestCase):
    """Role assignments are the only record of who did what, and they cascade."""

    def setUp(self):
        super().setUp()
        # The live proposal app owns these content types on a normal install;
        # on the awards site they are the fork's, left behind by the rename.
        # Either way the capture reads them by app_label and model.
        self.proposal_ct, _ = ContentType.objects.get_or_create(
            app_label="proposal", model="proposal"
        )
        self.call_ct, _ = ContentType.objects.get_or_create(
            app_label="proposal", model="call"
        )
        self.organisation_ct, _ = ContentType.objects.get_or_create(
            app_label="proposal", model="callmanagingorganisation"
        )
        self.manager_role = permission_models.Role.objects.create(
            name="PROPOSAL.MANAGER", is_system_role=True, content_type=self.proposal_ct
        )
        self.colead_role = permission_models.Role.objects.create(
            name="PROPOSAL.COLEAD", is_system_role=False, content_type=self.proposal_ct
        )
        self.organiser_role = permission_models.Role.objects.create(
            name="CUSTOMER.CALL_ORGANIZER",
            is_system_role=True,
            content_type=self.organisation_ct,
        )

    def grant(self, role, content_type, object_id, user=None, is_active=True):
        return permission_models.UserRole.objects.create(
            user=user or self.author,
            role=role,
            content_type=content_type,
            object_id=object_id,
            is_active=is_active,
        )

    def test_proposal_scoped_assignments_are_attached_to_their_proposal(self):
        self.grant(self.manager_role, self.proposal_ct, self.proposal_id)
        self.copy()
        membership = models.ArchivedMembership.objects.get()
        self.assertEqual(membership.scope_kind, "proposal")
        self.assertEqual(membership.proposal.uuid, self.proposal_uuid)
        self.assertEqual(membership.call.uuid, self.call_uuid)
        self.assertEqual(membership.role_name, "PROPOSAL.MANAGER")
        self.assertEqual(membership.user_username, "applicant")

    def test_a_custom_role_is_carried_by_name(self):
        self.grant(self.colead_role, self.proposal_ct, self.proposal_id)
        self.copy()
        self.assertEqual(
            models.ArchivedMembership.objects.get().role_name, "PROPOSAL.COLEAD"
        )

    def test_revoked_assignments_are_archived_too(self):
        self.grant(
            self.manager_role, self.proposal_ct, self.proposal_id, is_active=False
        )
        self.copy()
        self.assertIs(models.ArchivedMembership.objects.get().is_active, False)

    def test_organisation_scoped_assignments_carry_the_customer(self):
        self.grant(self.organiser_role, self.organisation_ct, self.organisation_id)
        self.copy()
        membership = models.ArchivedMembership.objects.get()
        self.assertEqual(membership.scope_kind, "organisation")
        self.assertEqual(membership.organisation_customer_uuid, self.customer.uuid)
        self.assertIsNone(membership.proposal)

    def test_assignments_pointing_at_a_deleted_proposal_are_not_archived(self):
        self.grant(self.manager_role, self.proposal_ct, 999999)
        self.copy()
        self.assertEqual(models.ArchivedMembership.objects.count(), 0)

    def test_memberships_are_cleared_by_a_re_run_rather_than_duplicated(self):
        self.grant(self.manager_role, self.proposal_ct, self.proposal_id)
        self.copy()
        self.copy()
        self.assertEqual(models.ArchivedMembership.objects.count(), 1)
