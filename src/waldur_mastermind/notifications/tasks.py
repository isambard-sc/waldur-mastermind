import logging
from celery import shared_task
from django.conf import settings
from django.utils import timezone

from waldur_core.core.utils import send_mail, format_mastermind_link

from . import models

logger = logging.getLogger(__name__)


def format_attachment_links(attachments):
    """Format attachment information for email body."""
    if not attachments:
        return ""

    lines = ["\n\n--- Attachments ---"]
    for attachment in attachments:
        # Build absolute URL for download
        file_url = format_mastermind_link(attachment.file.url)
        size_mb = attachment.size / (1024 * 1024)
        if size_mb >= 1:
            size_str = f"{size_mb:.2f} MB"
        else:
            size_kb = attachment.size / 1024
            size_str = f"{size_kb:.2f} KB"

        lines.append(f"• {attachment.filename} ({size_str})")
        lines.append(f"  Download: {file_url}")

    return "\n".join(lines)


@shared_task(name="waldur_mastermind.notifications.send_broadcast_message_email")
def send_broadcast_message_email(broadcast_message_uuid):
    broadcast_message = models.BroadcastMessage.objects.get(uuid=broadcast_message_uuid)
    emails = broadcast_message.emails

    logger.info(f"Sending broadcast message '{broadcast_message.subject}' to {emails}")

    # Get attachments and format download links
    attachments = broadcast_message.attachments.all()
    attachment_links = format_attachment_links(attachments)

    # Append attachment links to the email body
    email_body = broadcast_message.body
    if attachment_links:
        email_body = f"{broadcast_message.body}{attachment_links}"

    logger.info(f"Email body:\n{email_body}")

    for part in [emails[i : i + 50] for i in range(0, len(emails), 50)]:
        send_mail(
            broadcast_message.subject,
            email_body,
            [settings.DEFAULT_FROM_EMAIL],
            fail_silently=True,
            bcc=part,
        )

    broadcast_message.state = models.BroadcastMessage.States.SENT
    if not broadcast_message.send_at:
        broadcast_message.send_at = timezone.now()
    broadcast_message.save()


@shared_task(name="waldur_mastermind.notifications.send_scheduled_broadcast_messages")
def send_scheduled_broadcast_messages():
    """Send broadcast messages that have been scheduled for delivery."""
    messages = models.BroadcastMessage.objects.filter(
        state=models.BroadcastMessage.States.SCHEDULED, send_at__lte=timezone.now()
    )
    for message in messages:
        send_broadcast_message_email.delay(message.uuid.hex)
