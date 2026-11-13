from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel

from waldur_core.core import fields as core_fields
from waldur_core.core.models import User, UuidMixin


def _validate_http_url(value):
    """An http(s) URL with a host - not Django's URLValidator, which rejects
    the harness's bare in-cluster hostname."""
    if not value:
        return
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValidationError(_("Enter an http or https URL, including its host."))


class ReportingSession(UuidMixin, TimeStampedModel):
    """One AI reporting conversation. A user may have several - e.g. one per
    open browser tab - each with its own harness-side conversation, keyed
    by this model's uuid."""

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
    # A streaming status line - unused today, nothing writes to it yet;
    # kept so a future harness version has somewhere to put one.
    progress = models.TextField(blank=True, default="")
    # Filenames the harness created. Kept even if copying one into
    # ReportingFile below fails.
    new_files = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True, default="")
    # 0 for a pending/failed message - no Bedrock call completed.
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = _("AI reporting message")
        ordering = ["created"]
        indexes = [models.Index(fields=["session"])]

    def __str__(self):
        return f"ReportingMessage({self.status})"


class ReportingUsageRecord(TimeStampedModel):
    """One permanent record per AI reporting attempt, success or failure -
    tokens and outcome only, never the prompt/answer text. Retention
    cleanup deletes ReportingMessage rows, but never touches this one, so
    usage history survives even after the message it came from is gone.
    """

    class Status(models.TextChoices):
        DONE = "done", _("Done")
        FAILED = "failed", _("Failed")

    # SET_NULL, not CASCADE - usage history must survive the user being
    # removed too.
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="ai_reporting_usage_records",
    )
    status = models.CharField(max_length=10, choices=Status.choices)
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = _("AI reporting usage record")

    def __str__(self):
        return f"ReportingUsageRecord({self.status})"


class ReportingFile(UuidMixin, TimeStampedModel):
    """One file the harness produced for a ReportingMessage's answer, copied
    in once so it's served through Waldur's normal media access control
    instead of a separate proxy. A message may have zero to several."""

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
    get()), configured through the API like FormbricksConnection.

    signing_private_key is encrypted at rest and never returned by the API.
    Blank means requests go out unsigned, until the harness's own public
    key is configured too.
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
