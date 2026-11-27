import re
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

from waldur_core.core import fields as core_fields
from waldur_core.core.models import User, UuidMixin

# Questions and answers go to this URL, so it must be a Kubernetes Service
# name (<name>.<namespace>.svc[.cluster.local]): never a public host, an IP
# address or a bare name that could reach other internal services.
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_SERVICE_HOST = re.compile(rf"{_LABEL}(\.{_LABEL})+\.svc(\.cluster\.local)?")


def is_cluster_service_url(value: str) -> bool:
    # "@" and "\\" make urlsplit and requests disagree on the host.
    if not value or "@" in value or "\\" in value:
        return False
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or parts.query or parts.fragment:
        return False
    host = parts.hostname or ""
    try:
        sent_to = (parse_url(value).host or "").lower()
    except LocationParseError:
        return False
    return bool(_SERVICE_HOST.fullmatch(host)) and sent_to == host


def validate_http_url(value):
    """An http(s) URL to a Kubernetes Service - not Django's URLValidator,
    which accepts public hosts."""
    if not value:
        return
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValidationError(_("Enter an http or https URL, including its host."))
    if not is_cluster_service_url(value):
        raise ValidationError(
            _(
                "The harness must be a service inside the cluster, e.g. "
                "http://waldur-harness.waldur-harness.svc.cluster.local:8000."
            )
        )


class ReportingSession(UuidMixin, TimeStampedModel):
    """One AI reporting conversation. A user may have several, each with its
    own conversation on the harness side, keyed by this model's uuid."""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="ai_reporting_sessions"
    )

    class Meta:
        verbose_name = _("AI reporting session")
        ordering = ["created", "id"]

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
    # The harness's latest step, shown while the question runs.
    progress = models.TextField(blank=True, default="")
    # A short label from the harness for the Files and History lists.
    title = models.CharField(max_length=100, blank=True, default="")
    # Filenames the harness created. Kept even if copying one into
    # ReportingFile below fails.
    new_files = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True, default="")
    # Running totals while pending, then the final totals.
    input_tokens = models.PositiveIntegerField(default=0)
    output_tokens = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = _("AI reporting message")
        ordering = ["created", "id"]
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
    cache_read_tokens = models.PositiveIntegerField(default=0)
    cache_write_tokens = models.PositiveIntegerField(default=0)

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
        ordering = ["created", "id"]

    def __str__(self):
        return self.name


class HarnessConnection(TimeStampedModel):
    """The one AI reporting harness this site talks to. A single row (see
    get()), configured through the API like FormbricksConnection.

    signing_private_key is encrypted at rest and never returned by the API.
    The harness rejects unsigned requests, so it must be set.
    """

    base_url = models.CharField(
        max_length=500,
        default="http://waldur-harness.waldur-harness.svc.cluster.local:8000",
        validators=[validate_http_url],
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

    def endpoint(self, path: str) -> str:
        # Checked here too, in case a value was stored before the validator.
        if not is_cluster_service_url(self.base_url):
            raise ValueError("The harness URL is not an in-cluster address.")
        return self.base_url.rstrip("/") + path

    @property
    def is_signing_configured(self) -> bool:
        return bool(self.signing_private_key)
