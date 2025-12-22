from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from model_utils.fields import AutoCreatedField

from waldur_core.core.models import DescribableMixin, NameMixin, TimeStampedModel, User
from waldur_core.core.validators import validate_name
from waldur_core.logging.models import UuidMixin


class MessageTemplate(UuidMixin, NameMixin):
    body = models.TextField(blank=False)
    subject = models.TextField(blank=False)


class BroadcastMessage(UuidMixin):
    class States:
        DRAFT = "DRAFT"
        SCHEDULED = "SCHEDULED"
        SENT = "SENT"

        CHOICES = (
            (DRAFT, _("Draft")),
            (SCHEDULED, _("Scheduled")),
            (SENT, _("Sent")),
        )

    state = models.CharField(
        max_length=30, choices=States.CHOICES, default=States.DRAFT
    )
    send_at = models.DateField(null=True)
    author = models.ForeignKey(to=User, on_delete=models.SET_NULL, null=True)
    created = AutoCreatedField()
    subject = models.CharField(max_length=1000, validators=[validate_name])
    body = models.TextField(validators=[validate_name])
    query = models.JSONField()
    emails = models.JSONField()

    def __str__(self):
        return f"{self.subject} / {self.author} / {self.created}"


class BroadcastMessageAttachment(UuidMixin, TimeStampedModel):
    """File attachments for broadcast messages with download links."""

    broadcast_message = models.ForeignKey(
        BroadcastMessage,
        on_delete=models.CASCADE,
        related_name="attachments",
    )
    file = models.FileField(
        upload_to="broadcast_attachments",
        help_text="Attachment file for broadcast message",
    )
    filename = models.CharField(
        max_length=255,
        help_text="Original filename of the attachment",
    )
    size = models.PositiveIntegerField(
        help_text="File size in bytes",
    )
    uploaded_by = models.ForeignKey(
        to=User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="+",
    )

    class Meta:
        ordering = ["created"]

    def __str__(self):
        return f"{self.filename} ({self.size} bytes)"


class AdminAnnouncement(UuidMixin, DescribableMixin, TimeStampedModel):
    class Type:
        INFORMATION = "information"
        WARNING = "warning"
        DANGER = "danger"

        CHOICES = (
            (INFORMATION, _("Information")),
            (WARNING, _("Warning")),
            (DANGER, _("Danger")),
        )

    type = models.CharField(
        max_length=30, choices=Type.CHOICES, default=Type.INFORMATION
    )
    active_from = models.DateTimeField()
    active_to = models.DateTimeField()

    @property
    def is_active(self) -> bool:
        return self.active_from <= timezone.now() <= self.active_to
