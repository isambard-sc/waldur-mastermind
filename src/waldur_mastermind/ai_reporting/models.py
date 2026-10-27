from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel

from waldur_core.core.models import User, UuidMixin


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
    # Short status lines relayed from the harness as it works (e.g. "Turn 3:
    # calling run_code") - see PROJECT_LOG.md's progress-streaming design.
    # Not a transcript - just enough to show the user it's actually working.
    progress = models.TextField(blank=True, default="")
    # Filenames the harness reported for this answer. Kept even now that the
    # bytes are copied into ReportingFile below (see tasks.ask_harness) - a
    # cheap, always-present record of what the harness produced, independent
    # of whether any one file's copy succeeded.
    new_files = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True, default="")

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
