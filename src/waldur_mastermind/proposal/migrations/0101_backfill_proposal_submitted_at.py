from django.db import migrations
from django.db.models import F


def backfill_submitted_at(apps, schema_editor):
    """Give proposals submitted before ``submitted_at`` existed a submission
    time: when they were last changed, the closest record there is. Drafts
    stay empty; a canceled proposal is filled only if it was submitted, i.e.
    has the workflow steps that submission creates.

    Fork-only: upstream deliberately leaves these empty (see the field's
    help_text, kept as upstream's so the model merges cleanly).
    """
    Proposal = apps.get_model("proposal", "Proposal")
    missing = Proposal.objects.filter(submitted_at__isnull=True)
    missing.exclude(state__in=("draft", "canceled")).update(submitted_at=F("modified"))
    submitted_ids = apps.get_model(
        "proposal", "ProposalWorkflowStepInstance"
    ).objects.values("proposal_id")
    missing.filter(state="canceled", pk__in=submitted_ids).update(
        submitted_at=F("modified")
    )


class Migration(migrations.Migration):
    dependencies = [
        ("proposal", "0100_single_proposal_manager"),
    ]

    operations = [
        migrations.RunPython(backfill_submitted_at, migrations.RunPython.noop),
    ]
