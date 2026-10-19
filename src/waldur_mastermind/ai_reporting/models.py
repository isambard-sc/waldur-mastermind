from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils.models import TimeStampedModel

from waldur_core.core.models import User, UuidMixin


class ReportingSession(UuidMixin, TimeStampedModel):
    """One AI-reporting conversation per user, mirroring the harness's own
    one-conversation-per-identity model (see harness_manual_loop/http_service.py)."""

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="ai_reporting_session"
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
    # Filenames only - the bytes stay on the harness's own storage and are
    # proxied on demand, never copied into Waldur. See the ai_reporting design
    # notes for why (avoids both a blast-radius widening and unbounded DB growth).
    new_files = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = _("AI reporting message")
        ordering = ["created"]
        indexes = [models.Index(fields=["session"])]

    def __str__(self):
        return f"ReportingMessage({self.status})"
