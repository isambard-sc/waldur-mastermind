"""Read-only archive of the fork's own proposal app.

The awards site ran a fork-local proposal app that the upstream resync deleted
wholesale.  Its data is not migrated forward -- it is copied into these models
and the original tables are renamed aside (see
``docs/guides/awards-site-upgrade-plan.md``).

Two rules shape everything here:

* **Nothing points at live data.**  Every reference out of the archive is
  denormalised to a UUID plus a display value, so an archived proposal can
  neither block the deletion of the user who wrote it nor be cascaded away with
  a customer years from now.
* **Nothing is lost.**  Each row carries a ``payload`` holding the original
  record verbatim, including columns not modelled explicitly.

The original UUIDs are preserved, so old ``/proposals/<uuid>`` links can still
be resolved.
"""

from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel

from waldur_core.core import models as core_models


class ArchiveBase(TimeStampedModel, core_models.UuidMixin):
    """Common shape of every archived record.

    ``created``/``modified`` come from ``TimeStampedModel`` but are copied from
    the source row rather than set on insert, so the archive keeps the original
    timeline.  Both are therefore writable here, unlike on a live model.

    Every field holding copied text is a ``TextField``, deliberately, even where
    the source column was a bounded ``CharField``.  An archive that refuses a
    row because the live model happened to cap a description at 2,000
    characters is not an archive -- and the fork's proposals do exceed it.  The
    only bounded fields left are ``scope_kind``, which the archive invents
    rather than copies, and the two ``FileField``s, which cannot be text and are
    capped at 255 to match ``media_file.name``.
    """

    payload = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("The original database row, verbatim."),
    )

    class Meta:
        abstract = True


class ArchivedCall(ArchiveBase):
    """A call for proposals, with its managing organisation denormalised onto it."""

    name = models.TextField()
    slug = models.TextField(blank=True)
    description = models.TextField(blank=True)
    state = models.TextField(blank=True)
    external_url = models.TextField(blank=True, null=True)

    reviewer_identity_visible_to_submitters = models.BooleanField(default=False)
    reviews_visible_to_submitters = models.BooleanField(default=True)
    fixed_duration_in_days = models.PositiveIntegerField(null=True, blank=True)

    # CallManagingOrganisation, flattened.  Kept as the organisation's own uuid
    # *and* the customer's, because §4.2 grants access by customer.
    manager_uuid = models.UUIDField(null=True, blank=True)
    customer_uuid = models.UUIDField(null=True, blank=True, db_index=True)
    customer_name = models.TextField(blank=True)

    created_by_uuid = models.UUIDField(null=True, blank=True)
    created_by_username = models.TextField(blank=True)
    created_by_full_name = models.TextField(blank=True)

    class Meta:
        verbose_name = _("Archived call")
        ordering = ["-created", "id"]

    def __str__(self):
        return self.name


class ArchivedRound(ArchiveBase):
    """A submission round within an archived call."""

    call = models.ForeignKey(
        ArchivedCall, on_delete=models.CASCADE, related_name="rounds"
    )
    slug = models.TextField(blank=True)

    start_time = models.DateTimeField(null=True, blank=True)
    cutoff_time = models.DateTimeField(null=True, blank=True)
    review_strategy = models.TextField(blank=True)
    deciding_entity = models.TextField(blank=True)
    allocation_time = models.TextField(blank=True)
    allocation_date = models.DateTimeField(null=True, blank=True)
    review_duration_in_days = models.PositiveIntegerField(null=True, blank=True)
    fixed_review_end_date = models.DateTimeField(null=True, blank=True)
    minimum_number_of_reviewers = models.PositiveIntegerField(null=True, blank=True)
    minimal_average_scoring = models.DecimalField(
        max_digits=6, decimal_places=2, null=True, blank=True
    )
    minimum_required_uploads = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        verbose_name = _("Archived round")
        ordering = ["-start_time", "id"]

    def __str__(self):
        return f"{self.call} / {self.slug or self.uuid}"


class ArchivedProposal(ArchiveBase):
    """A submitted proposal.

    ``call`` duplicates ``round.call`` so that the permission filter of §4.2 --
    which is by call -- does not need a join through rounds on every query.
    """

    round = models.ForeignKey(
        ArchivedRound, on_delete=models.CASCADE, related_name="proposals"
    )
    call = models.ForeignKey(
        ArchivedCall, on_delete=models.CASCADE, related_name="proposals"
    )

    name = models.TextField()
    slug = models.TextField(blank=True)
    description = models.TextField(blank=True)
    state = models.TextField(blank=True)

    duration_in_days = models.PositiveIntegerField(null=True, blank=True)
    project_summary = models.TextField(blank=True)
    project_duration = models.PositiveIntegerField(null=True, blank=True)
    project_is_confidential = models.BooleanField(default=False)
    project_has_civilian_purpose = models.BooleanField(default=False)
    oecd_fos_2007_code = models.TextField(blank=True)

    allocation_comment = models.TextField(blank=True, null=True)
    submitted_at = models.DateTimeField(null=True, blank=True)
    notes = models.JSONField(
        default=list,
        blank=True,
        help_text=_("Call-manager notes: {timestamp, author, text}."),
    )

    project_uuid = models.UUIDField(null=True, blank=True, db_index=True)
    project_name = models.TextField(blank=True)
    created_by_uuid = models.UUIDField(null=True, blank=True, db_index=True)
    created_by_username = models.TextField(blank=True)
    created_by_full_name = models.TextField(blank=True)
    approved_by_uuid = models.UUIDField(null=True, blank=True)
    approved_by_username = models.TextField(blank=True)

    class Meta:
        verbose_name = _("Archived proposal")
        ordering = ["-created", "id"]

    def __str__(self):
        return self.name


class ArchivedRequestedResource(ArchiveBase):
    """A resource requested by an archived proposal.

    ``RequestedOffering`` and ``CallResourceTemplate`` are flattened into this,
    since neither is interesting on its own once the call is closed.
    """

    proposal = models.ForeignKey(
        ArchivedProposal, on_delete=models.CASCADE, related_name="requested_resources"
    )

    offering_uuid = models.UUIDField(null=True, blank=True)
    offering_name = models.TextField(blank=True)
    plan_uuid = models.UUIDField(null=True, blank=True)
    plan_name = models.TextField(blank=True)
    template_name = models.TextField(blank=True)

    attributes = models.JSONField(default=dict, blank=True)
    limits = models.JSONField(default=dict, blank=True)
    resource_uuid = models.UUIDField(null=True, blank=True)

    created_by_uuid = models.UUIDField(null=True, blank=True)
    created_by_username = models.TextField(blank=True)

    class Meta:
        verbose_name = _("Archived requested resource")
        ordering = ["created", "id"]

    def __str__(self):
        return f"{self.offering_name or self.uuid}"


class ArchivedReview(ArchiveBase):
    """A review of an archived proposal.

    Reviewer identity and comment text are administrator-only in the archive,
    whatever the original call's visibility flags said -- see §4.2 of the plan.
    ``ReviewComment`` was never used in production (zero rows), so its messages
    are folded into ``comments`` rather than given a model.
    """

    proposal = models.ForeignKey(
        ArchivedProposal, on_delete=models.CASCADE, related_name="reviews"
    )

    state = models.TextField(blank=True)
    summary_score = models.PositiveSmallIntegerField(default=0)
    summary_public_comment = models.TextField(blank=True)
    summary_private_comment = models.TextField(blank=True)

    comment_project_title = models.TextField(blank=True, null=True)
    comment_project_summary = models.TextField(blank=True, null=True)
    comment_project_description = models.TextField(blank=True, null=True)
    comment_project_duration = models.TextField(blank=True, null=True)
    comment_project_is_confidential = models.TextField(blank=True, null=True)
    comment_project_has_civilian_purpose = models.TextField(blank=True, null=True)
    comment_project_supporting_documentation = models.TextField(blank=True, null=True)
    comment_resource_requests = models.TextField(blank=True, null=True)
    comment_team = models.TextField(blank=True, null=True)

    reviewer_uuid = models.UUIDField(null=True, blank=True)
    reviewer_username = models.TextField(blank=True)
    reviewer_full_name = models.TextField(blank=True)

    comments = models.JSONField(
        default=list,
        blank=True,
        help_text=_("Review conversation: {created, message}."),
    )

    class Meta:
        verbose_name = _("Archived review")
        ordering = ["created", "id"]

    def __str__(self):
        return f"Review of {self.proposal_id}"


class ArchivedCallDocument(ArchiveBase):
    """A file attached to an archived call.

    The prefix differs from the live app's ``call_documents`` on purpose:
    ``access.register()`` raises on a duplicate prefix, and if the archive
    shared it the live rule would answer for these files and deny every one.
    The copy renames ``media_file.name`` accordingly; no bytes move.
    """

    call = models.ForeignKey(
        ArchivedCall, on_delete=models.CASCADE, related_name="documents"
    )
    description = models.TextField(blank=True)
    file = models.FileField(
        upload_to="archived_call_documents",
        max_length=255,
        blank=True,
        null=True,
    )

    class Meta:
        verbose_name = _("Archived call document")
        ordering = ["created", "id"]


class ArchivedProposalDocument(ArchiveBase):
    """Supporting documentation uploaded with an archived proposal.

    Separate prefix, for the same reason as ``ArchivedCallDocument``.
    """

    proposal = models.ForeignKey(
        ArchivedProposal, on_delete=models.CASCADE, related_name="documents"
    )
    file = models.FileField(
        upload_to="archived_proposal_documentation",
        max_length=255,
        blank=True,
        null=True,
    )

    class Meta:
        verbose_name = _("Archived proposal document")
        ordering = ["created", "id"]


class ArchivedMembership(ArchiveBase):
    """Who held which role on an archived call or proposal.

    Deleting the fork's proposal roles cascades their ``UserRole`` rows away,
    and those rows are the only record of who managed, co-led and reviewed each
    proposal.  They are captured here first.

    Two of the seven roles were custom rather than system roles, so the role is
    carried as text: there is no enum to map it back to.
    """

    class Scopes:
        CALL = "call"
        PROPOSAL = "proposal"
        ORGANISATION = "organisation"

        CHOICES = (
            (CALL, "Call"),
            (PROPOSAL, "Proposal"),
            (ORGANISATION, "Call managing organisation"),
        )

    scope_kind = models.CharField(max_length=20, choices=Scopes.CHOICES, db_index=True)
    call = models.ForeignKey(
        ArchivedCall,
        on_delete=models.CASCADE,
        related_name="memberships",
        null=True,
        blank=True,
    )
    proposal = models.ForeignKey(
        ArchivedProposal,
        on_delete=models.CASCADE,
        related_name="memberships",
        null=True,
        blank=True,
    )

    # Organisation-scoped grants (CUSTOMER.CALL_ORGANIZER, "Call Reader") have
    # no archived object to hang off -- the managing organisation is flattened
    # onto each call -- so they carry the customer directly.
    organisation_customer_uuid = models.UUIDField(null=True, blank=True)
    organisation_customer_name = models.TextField(blank=True)

    role_name = models.TextField(db_index=True)
    role_description = models.TextField(blank=True)

    user_uuid = models.UUIDField(null=True, blank=True, db_index=True)
    user_username = models.TextField(blank=True)
    user_full_name = models.TextField(blank=True)

    is_active = models.BooleanField(null=True, default=True)
    expiration_time = models.DateTimeField(null=True, blank=True)
    granted_by_username = models.TextField(blank=True)
    revoked_by_username = models.TextField(blank=True)
    revoke_reason = models.TextField(blank=True)

    class Meta:
        verbose_name = _("Archived membership")
        ordering = ["-created", "id"]

    def __str__(self):
        return f"{self.user_username} as {self.role_name}"
