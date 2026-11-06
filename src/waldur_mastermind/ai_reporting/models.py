from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel

from waldur_core.core import fields as core_fields
from waldur_core.core.models import User, UuidMixin


def _validate_http_url(value):
    """An http(s) URL with a host. Not Django's URLValidator: that insists on
    a dotted domain, and the harness is reached by a bare in-cluster service
    name ("http://waldur-harness.waldur-harness.svc.cluster.local:8000"),
    which it would reject. Same validator proposal_forms.models uses for
    FormbricksConnection's URLs, for the same reason."""
    if not value:
        return
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValidationError(_("Enter an http or https URL, including its host."))


class ReportingSession(UuidMixin, TimeStampedModel):
    """One AI-reporting conversation. A user may have several - e.g. one per
    open browser tab - each mapped to its own harness-side conversation
    (keyed by this model's uuid; see harness_manual_loop/http_service.py)."""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="ai_reporting_sessions"
    )

    class Meta:
        verbose_name = _("AI reporting session")

    def __str__(self):
        return f"ReportingSession({self.user.username})"


class ReportingMessage(UuidMixin, TimeStampedModel):
    """One prompt -> one answer. Flatter than chat's session/thread/message
    split - the harness is one conversation per identity, not threaded."""

    class Status(models.TextChoices):
        PENDING = "pending", _("Pending")
        DONE = "done", _("Done")
        FAILED = "failed", _("Failed")

    session = models.ForeignKey(
        ReportingSession, on_delete=models.CASCADE, related_name="messages"
    )
    prompt = models.TextField()
    answer = models.TextField(blank=True, default="")
    status = models.CharField(
        max_length=10, choices=Status.choices, default=Status.PENDING
    )
    # Meant to hold a short status line relayed from the harness mid-answer
    # (e.g. "Turn 3: calling run_code"), not a full transcript - just enough
    # to show the user it's actually working while they wait. Nothing writes
    # to this field today: a single ask_harness call blocks until the harness
    # returns a finished answer, with no mid-flight updates coming back to
    # record here, so in practice this is always blank, and the frontend
    # shows rotating placeholder text instead (AIReportingPage.tsx's
    # PENDING_PHASES) while it waits. Kept so a future version of the harness
    # that does stream real progress has a field to write it into, without a
    # schema change at that point.
    progress = models.TextField(blank=True, default="")
    # Filenames the harness reported for this answer. Kept even now that the
    # bytes are copied into ReportingFile below (see tasks.ask_harness) - a
    # cheap, always-present record of what the harness produced, independent
    # of whether any one file's copy succeeded.
    new_files = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True, default="")
    # From the harness's /query response "usage" object (see run_agent.run's
    # usage_out) - 0 for a pending/failed message, since no Bedrock call
    # completed. Backs both the AI_REPORTING_TOKEN_LIMIT_*/GLOBAL_* Constance
    # enforcement (ai_reporting.limits) and the usage-visibility report.
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = _("AI reporting message")
        ordering = ["created"]
        indexes = [models.Index(fields=["session"])]

    def __str__(self):
        return f"ReportingMessage({self.status})"


class ReportingFile(UuidMixin, TimeStampedModel):
    """One file the harness produced for a ReportingMessage's answer, copied
    in once from the harness's own storage (see tasks.ask_harness) so it's
    served through Waldur's normal media access control instead of a
    separate proxy. A message may have zero to several of these."""

    message = models.ForeignKey(
        ReportingMessage, on_delete=models.CASCADE, related_name="files"
    )
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to="ai_reporting/")

    class Meta:
        verbose_name = _("AI reporting file")

    def __str__(self):
        return self.name


class HarnessConnection(TimeStampedModel):
    """The one AI reporting harness this site talks to. A single row (see
    get()) - configured through the API
    (/api/ai-reporting-harness-connection/) rather than baked into deployment
    settings, the same way proposal_forms.models.FormbricksConnection is.

    signing_private_key is encrypted at rest and never returned by the API.
    Blank (the default) means every call to the harness goes out unsigned:
    the harness only starts requiring a signature once its own
    WALDUR_SIGNING_PUBLIC_KEY is configured, so an unsigned request is
    accepted exactly as it always has been until both sides are set up.
    """

    base_url = models.CharField(
        max_length=500,
        default="http://waldur-harness.waldur-harness.svc.cluster.local:8000",
        validators=[_validate_http_url],
        help_text=_(
            "In-cluster address of the AI reporting harness's HTTP wrapper "
            "(http_service.py in the waldur-ai-harness repo)."
        ),
    )
    signing_private_key = core_fields.EncryptedTextField(
        blank=True,
        default="",
        help_text=_(
            "Base64-encoded raw Ed25519 private key bytes, used to sign every "
            "request to the harness so it can verify the request genuinely "
            "came from Waldur. See signing.py's own module docstring for a "
            "ready-to-run snippet that generates a real keypair."
        ),
    )

    class Meta:
        verbose_name = _("AI reporting harness connection")

    def __str__(self):
        return self.base_url

    @classmethod
    def get(cls) -> "HarnessConnection":
        connection, _created = cls.objects.get_or_create(pk=1)
        return connection

    @property
    def is_signing_configured(self) -> bool:
        return bool(self.signing_private_key)
