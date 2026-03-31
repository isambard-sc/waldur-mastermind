import logging
from decimal import Decimal

from django.utils import timezone

from waldur_openportal import models

logger = logging.getLogger(__name__)


def get_or_create_remote_project(allocation, destination: str):
    """
    Get or create a RemoteProject for (destination, identifier).

    identifier = str(allocation.get_project_identifier())

    On create: sets remote_allocation, current_project, state=PENDING.
    On get: if remote_allocation or current_project differ, update them.
    """
    identifier = str(allocation.get_project_identifier())

    remote_project, created = models.RemoteProject.objects.get_or_create(
        destination=destination,
        identifier=identifier,
        defaults={
            "remote_allocation": allocation,
            "current_project": allocation.project,
            "state": models.RemoteProjectState.PENDING,
        },
    )

    if not created:
        changed = False
        if remote_project.remote_allocation != allocation:
            remote_project.remote_allocation = allocation
            changed = True
        if remote_project.current_project != allocation.project:
            remote_project.current_project = allocation.project
            changed = True
        if changed:
            remote_project.save()

    return remote_project


def ensure_current_attachment(remote_project):
    """
    Ensure there is an open RemoteProjectAttachment for
    remote_project.current_project.

    Closes (sets detached_at=now) any open attachment pointing to a
    different project, then get_or_creates the open attachment for the
    current project.
    """
    now = timezone.now()
    current_project = remote_project.current_project

    # Close any open attachments for a different project
    models.RemoteProjectAttachment.objects.filter(
        remote_project=remote_project,
        detached_at__isnull=True,
    ).exclude(project=current_project).update(detached_at=now)

    # Get or create the open attachment for the current project
    attachment, _ = models.RemoteProjectAttachment.objects.get_or_create(
        remote_project=remote_project,
        project=current_project,
        detached_at__isnull=True,
    )

    return attachment


def record_award_created(
    remote_project,
    details_json,
    allocation_value=None,
    attachment=None,
):
    """
    Called when add_project() succeeds on the remote portal
    (synchronous confirmation).

    Creates a confirmed RemoteProjectAllocationEntry if allocation_value
    is not None.
    Sets: last_sent_details, last_confirmed_details,
          pending_details=None, pending_since=None,
          state=ACTIVE, last_contact_time=now,
          current_allocation=allocation_value (if given).
    Creates audit entry with event_type=AWARD_CREATED.
    """
    now = timezone.now()

    allocation_entry = None
    if allocation_value is not None:
        allocation_entry = (
            models.RemoteProjectAllocationEntry.objects.create(
                remote_project=remote_project,
                allocation=Decimal(str(allocation_value)),
                previous_allocation=remote_project.current_allocation,
                attachment=attachment,
                source_project=remote_project.current_project,
                confirmed_at=now,
            )
        )

    remote_project.last_sent_details = details_json
    remote_project.last_confirmed_details = details_json
    remote_project.pending_details = None
    remote_project.pending_since = None
    remote_project.state = models.RemoteProjectState.ACTIVE
    remote_project.last_contact_time = now

    if allocation_value is not None:
        remote_project.current_allocation = Decimal(str(allocation_value))

    remote_project.save()

    audit_entry = models.RemoteProjectAuditEntry.objects.create(
        remote_project=remote_project,
        event_type=models.RemoteProjectAuditEventType.AWARD_CREATED,
        new_details=details_json,
        allocation_entry=allocation_entry,
    )

    return audit_entry


def record_award_sent(
    remote_project,
    details_json,
    allocation_value=None,
    attachment=None,
):
    """
    Called when update_award is about to be sent (before the network
    call).

    Creates a pending RemoteProjectAllocationEntry (confirmed_at=None)
    if allocation_value differs from current_allocation.
    Sets: last_sent_details, pending_details, pending_since=now.
    Creates audit entry with event_type=AWARD_UPDATED.
    """
    now = timezone.now()

    allocation_entry = None
    if allocation_value is not None:
        current = remote_project.current_allocation
        if Decimal(str(allocation_value)) != current:
            allocation_entry = (
                models.RemoteProjectAllocationEntry.objects.create(
                    remote_project=remote_project,
                    allocation=Decimal(str(allocation_value)),
                    previous_allocation=current,
                    attachment=attachment,
                    source_project=remote_project.current_project,
                    confirmed_at=None,
                )
            )

    remote_project.last_sent_details = details_json
    remote_project.pending_details = details_json
    remote_project.pending_since = now
    remote_project.save()

    audit_entry = models.RemoteProjectAuditEntry.objects.create(
        remote_project=remote_project,
        event_type=models.RemoteProjectAuditEventType.AWARD_UPDATED,
        previous_details=remote_project.last_confirmed_details,
        new_details=details_json,
        allocation_entry=allocation_entry,
    )

    return audit_entry


def record_award_update_confirmed(
    remote_project,
    details_json,
    allocation_value=None,
    attachment=None,
):
    """
    Called when update_award is confirmed by the remote portal.

    Finds the most recent unconfirmed RemoteProjectAllocationEntry and
    sets confirmed_at=now.  If none found, creates a new confirmed entry.
    Sets: last_confirmed_details, pending_details=None,
          pending_since=None, state=ACTIVE, last_contact_time=now,
          current_allocation (if given), pending_allocation=None.
    Creates audit entry with event_type=AWARD_UPDATE_CONFIRMED.
    """
    now = timezone.now()

    allocation_entry = None
    if allocation_value is not None:
        unconfirmed = (
            models.RemoteProjectAllocationEntry.objects.filter(
                remote_project=remote_project,
                confirmed_at__isnull=True,
            )
            .order_by("-submitted_at")
            .first()
        )

        if unconfirmed is not None:
            unconfirmed.confirmed_at = now
            unconfirmed.save()
            allocation_entry = unconfirmed
        else:
            allocation_entry = (
                models.RemoteProjectAllocationEntry.objects.create(
                    remote_project=remote_project,
                    allocation=Decimal(str(allocation_value)),
                    previous_allocation=remote_project.current_allocation,
                    attachment=attachment,
                    source_project=remote_project.current_project,
                    confirmed_at=now,
                )
            )

    remote_project.last_confirmed_details = details_json
    remote_project.pending_details = None
    remote_project.pending_since = None
    remote_project.state = models.RemoteProjectState.ACTIVE
    remote_project.last_contact_time = now
    remote_project.pending_allocation = None

    if allocation_value is not None:
        remote_project.current_allocation = Decimal(str(allocation_value))

    remote_project.save()

    audit_entry = models.RemoteProjectAuditEntry.objects.create(
        remote_project=remote_project,
        event_type=(
            models.RemoteProjectAuditEventType.AWARD_UPDATE_CONFIRMED
        ),
        new_details=details_json,
        allocation_entry=allocation_entry,
    )

    return audit_entry


def record_award_update_rejected(
    remote_project, error_message, remote_response=None
):
    """
    Called when update_award is rejected (ManagedProjectRejectedError).

    Sets: state=ERROR.
    Creates audit entry with event_type=AWARD_UPDATE_REJECTED,
    remote_response=remote_response or {"error": error_message},
    note=error_message.
    """
    remote_project.state = models.RemoteProjectState.ERROR
    remote_project.save()

    response_data = (
        remote_response
        if remote_response is not None
        else {"error": error_message}
    )

    audit_entry = models.RemoteProjectAuditEntry.objects.create(
        remote_project=remote_project,
        event_type=(
            models.RemoteProjectAuditEventType.AWARD_UPDATE_REJECTED
        ),
        remote_response=response_data,
        note=error_message,
    )

    return audit_entry


def touch_last_contact(remote_project):
    """
    Record that we have just received a live response from the remote
    portal about this project (e.g. a successful usage or storage report
    fetch).

    Updates last_contact_time to now.  If the project was STALE,
    transitions it back to ACTIVE — hearing from the portal means the
    connection is healthy.
    """
    now = timezone.now()
    update_fields = ["last_contact_time", "modified"]

    remote_project.last_contact_time = now

    if remote_project.state == models.RemoteProjectState.STALE:
        remote_project.state = models.RemoteProjectState.ACTIVE
        update_fields.append("state")

    remote_project.save(update_fields=update_fields)


def record_resource_deleted(remote_project, note=""):
    """
    Called when delete_allocation() succeeds.

    Closes all open RemoteProjectAttachment (sets detached_at=now).
    Sets: remote_allocation=None, state=DELETED.
    Creates audit entry with event_type=RESOURCE_DELETED, note=note.
    """
    now = timezone.now()

    # Close all open attachments
    models.RemoteProjectAttachment.objects.filter(
        remote_project=remote_project,
        detached_at__isnull=True,
    ).update(detached_at=now)

    remote_project.remote_allocation = None
    remote_project.state = models.RemoteProjectState.DELETED
    remote_project.save()

    audit_entry = models.RemoteProjectAuditEntry.objects.create(
        remote_project=remote_project,
        event_type=models.RemoteProjectAuditEventType.RESOURCE_DELETED,
        note=note,
    )

    return audit_entry
