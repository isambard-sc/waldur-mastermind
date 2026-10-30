from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel

from waldur_core.core import fields as core_fields
from waldur_core.core import models as core_models
from waldur_core.structure import models as structure_models
from waldur_mastermind.proposal import models as proposal_models


def validate_http_url(value):
    """An http(s) URL with a host.

    Not Django's URLValidator: that insists on a dotted domain, and the
    server-side Management API is often reached by a bare in-cluster service
    name ("http://formbricks:3000").
    """
    if not value:
        return
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValidationError(_("Enter an http or https URL, including its host."))


class FormbricksConnection(TimeStampedModel):
    """The one Formbricks server this site uses. A single row (see get()).

    Configured through the API (/api/formbricks-connection/), like an identity
    provider, rather than in deployment settings. The API key and webhook
    secret are encrypted at rest and never returned by the API.
    """

    enabled = models.BooleanField(
        default=False,
        help_text=_(
            "Whether calls may take applications through Formbricks. Can only be "
            "switched on once the URL, API key and webhook secret are set."
        ),
    )
    base_url = models.CharField(
        max_length=500,
        blank=True,
        validators=[validate_http_url],
        help_text=_(
            "Public URL of the Formbricks server, as applicants' browsers reach "
            "it. Survey links are built from it."
        ),
    )
    management_api_url = models.CharField(
        max_length=500,
        blank=True,
        validators=[validate_http_url],
        help_text=_(
            "URL this server uses for the Formbricks Management API, if it differs "
            "from the public URL (for example an in-cluster service name). Blank "
            "means the public URL."
        ),
    )
    api_key = core_fields.EncryptedTextField(blank=True, default="")
    webhook_secret = core_fields.EncryptedTextField(blank=True, default="")

    class Meta:
        verbose_name = _("Formbricks connection")

    def __str__(self):
        return self.base_url or "Formbricks connection (not configured)"

    @classmethod
    def get(cls) -> "FormbricksConnection":
        connection, _ = cls.objects.get_or_create(pk=1)
        return connection

    @property
    def management_base_url(self) -> str:
        return (self.management_api_url or self.base_url).rstrip("/")

    @property
    def public_base_url(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.webhook_secret)

    @property
    def is_active(self) -> bool:
        return self.enabled and self.is_configured


class FormFlow(core_models.UuidMixin, TimeStampedModel):
    """A chain of Formbricks surveys filled in step by step: by applicants
    for their proposal, or by a project's PI when the project ends.

    steps is a list of step definitions, checked when saved through the API
    (see flows.validate_steps): each step has a key, a label, the Formbricks
    survey_id and whether reviewers may read its answers.
    """

    key = models.SlugField(
        max_length=100,
        unique=True,
        help_text=_("Identifier calls refer to the flow by, e.g. 'airr-gw'."),
    )

    class Purposes:
        APPLICATION = "application"  # filled in for a proposal, before submission
        CLOSING = "closing"  # filled in for a project, when it ends

        CHOICES = (
            (APPLICATION, "Application"),
            (CLOSING, "End of project"),
        )

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    purpose = models.CharField(
        max_length=20,
        choices=Purposes.CHOICES,
        default=Purposes.APPLICATION,
        help_text=_(
            "What the flow is filled in for: a proposal (application) or a "
            "project at its end (closing). Decides the surveys' hidden fields "
            "and the page their endings return to."
        ),
    )
    steps = models.JSONField(default=list)
    survey_schemas = models.JSONField(
        default=dict,
        blank=True,
        help_text=_(
            "What each step's survey asks, as read from Formbricks at the last "
            "sync: {survey_id: {name, questions: [{id, type, label, choices}]}}."
        ),
    )

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class CallFormFlow(TimeStampedModel):
    """Which flows a call uses: the one its applicants fill in (none: Waldur's
    own proposal form alone), and the one the PIs of the projects it grants
    fill in when their project ends (none: no end-of-project forms)."""

    call = models.OneToOneField(
        proposal_models.Call,
        on_delete=models.CASCADE,
        related_name="form_flow_link",
    )
    flow = models.ForeignKey(
        FormFlow,
        on_delete=models.PROTECT,
        related_name="call_links",
        null=True,
        blank=True,
    )
    closing_flow = models.ForeignKey(
        FormFlow,
        on_delete=models.PROTECT,
        related_name="closing_call_links",
        null=True,
        blank=True,
    )
    closing_forms_open_days_before_end = models.PositiveIntegerField(
        default=0,
        help_text=_(
            "How many days before a project's end date its end-of-project "
            "forms open. 0: on the end date. They stay open afterwards."
        ),
    )

    def __str__(self):
        return f"{self.call} -> {self.flow}"


class SiteClosingFormFlow(TimeStampedModel):
    """The end-of-project flow for projects whose call has none: those no
    call granted (awards made before calls were used, or outside them) and
    those of calls without one. A single row (see get()). It may be limited
    to some organisations' projects; none listed means every organisation."""

    flow = models.ForeignKey(
        FormFlow,
        on_delete=models.PROTECT,
        related_name="+",
        null=True,
        blank=True,
    )
    closing_forms_open_days_before_end = models.PositiveIntegerField(
        default=0,
        help_text=_(
            "How many days before a project's end date its end-of-project "
            "forms open. 0: on the end date. They stay open afterwards."
        ),
    )
    customers = models.ManyToManyField(
        structure_models.Customer,
        blank=True,
        related_name="+",
        help_text=_(
            "The organisations whose projects use the flow; none: every organisation."
        ),
    )

    @classmethod
    def get(cls) -> "SiteClosingFormFlow":
        default, _ = cls.objects.get_or_create(pk=1)
        return default

    def applies_to(self, project) -> bool:
        if self.flow_id is None:
            return False
        if not self.customers.exists():
            return True
        return self.customers.filter(pk=project.customer_id).exists()


class ClosingFormsNotice(TimeStampedModel):
    """That a project's PI was told its end-of-project forms are open, so
    they are told once."""

    project = models.OneToOneField(
        structure_models.Project,
        on_delete=models.CASCADE,
        related_name="closing_forms_notice",
    )


class FormLink(TimeStampedModel):
    """A single-use survey link Waldur issued for one form of a proposal (an
    application form) or of a project (an end-of-project form): exactly one
    of the two is set.

    Formbricks gives each link an id (suId) and records it on the response
    made through it; that id is how Waldur knows whose response it is.
    """

    class States:
        ISSUED = "issued"  # handed out, no finished response yet
        ANSWERED = "answered"  # its response holds the form's current answers
        SUPERSEDED = "superseded"  # answered, then replaced by an edit
        LATE = "late"  # finished after the proposal was submitted: not applied

        CHOICES = (
            (ISSUED, "Issued"),
            (ANSWERED, "Answered"),
            (SUPERSEDED, "Superseded"),
            (LATE, "Late"),
        )

    single_use_id = models.CharField(max_length=255, unique=True)
    proposal = models.ForeignKey(
        proposal_models.Proposal,
        on_delete=models.CASCADE,
        related_name="form_links",
        null=True,
        blank=True,
    )
    project = models.ForeignKey(
        structure_models.Project,
        on_delete=models.CASCADE,
        related_name="closing_form_links",
        null=True,
        blank=True,
    )
    step_key = models.CharField(max_length=100)
    survey_id = models.CharField(max_length=100)
    url = models.TextField(help_text=_("The link as handed out."))
    issued_to = models.ForeignKey(
        core_models.User, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    state = models.CharField(
        max_length=20, choices=States.CHOICES, default=States.ISSUED, db_index=True
    )
    response_id = models.CharField(max_length=100, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(proposal__isnull=False, project__isnull=True)
                | models.Q(proposal__isnull=True, project__isnull=False),
                name="proposal_forms_link_one_subject",
            )
        ]

    @property
    def subject(self):
        return self.proposal or self.project

    def __str__(self):
        return f"{self.subject} / {self.step_key} / {self.single_use_id}"


class FormbricksDeletion(TimeStampedModel):
    """A Formbricks response Waldur is to delete: one an edit replaced, or one
    of a draft proposal that was deleted. Kept until Formbricks confirms, so
    an unreachable Formbricks only delays it. Not linked to the proposal,
    which may be gone."""

    response_id = models.CharField(max_length=100, unique=True)
    reason = models.CharField(max_length=200)
    attempts = models.PositiveIntegerField(default=0)
    last_error = models.TextField(blank=True)

    def __str__(self):
        return self.response_id


class FormStepResponse(core_models.UuidMixin, TimeStampedModel):
    """An applicant's answers to one step, as Formbricks has them.

    Written from the webhook or a fetch, and updated when Formbricks changes
    (it is the source of truth). The question labels are captured at the same
    moment, so the answers always read as the questions were worded when the
    applicant saw them, whatever happens to the survey afterwards.
    """

    class Permissions:
        customer_path = "proposal__round__call__manager__customer"

    proposal = models.ForeignKey(
        proposal_models.Proposal,
        on_delete=models.CASCADE,
        related_name="form_step_responses",
        null=True,
        blank=True,
    )
    project = models.ForeignKey(
        structure_models.Project,
        on_delete=models.CASCADE,
        related_name="closing_form_responses",
        null=True,
        blank=True,
    )
    step_key = models.CharField(max_length=100)
    survey_id = models.CharField(max_length=100)
    response_id = models.CharField(max_length=100)
    link = models.ForeignKey(
        FormLink, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    raw_response = models.JSONField(default=dict, blank=True)
    question_labels = models.JSONField(default=dict, blank=True)
    # jsonb does not keep object key order, so the order the questions were
    # asked in is kept separately, as an array.
    question_order = models.JSONField(default=list, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(proposal__isnull=False, project__isnull=True)
                | models.Q(proposal__isnull=True, project__isnull=False),
                name="proposal_forms_response_one_subject",
            ),
            models.UniqueConstraint(
                fields=["proposal", "step_key"],
                condition=models.Q(proposal__isnull=False),
                name="proposal_forms_response_proposal_step",
            ),
            models.UniqueConstraint(
                fields=["project", "step_key"],
                condition=models.Q(project__isnull=False),
                name="proposal_forms_response_project_step",
            ),
        ]

    @property
    def subject(self):
        return self.proposal or self.project

    def __str__(self):
        return f"{self.subject} / {self.step_key}"
