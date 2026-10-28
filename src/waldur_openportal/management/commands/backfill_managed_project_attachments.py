from django.core.management.base import BaseCommand
from django.db import transaction

from waldur_openportal import utils


class Command(BaseCommand):
    help = (
        "Give awards that predate the audit log a first attachment from their "
        "project's start, so their earlier usage counts as theirs."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change, and change nothing.",
        )

    def handle(self, *args, **options):
        with transaction.atomic():
            summary = utils.backfill_managed_project_attachments(
                dry_run=options["dry_run"]
            )
            if options["dry_run"]:
                # get_attachments() reconstructs a missing history as it reads
                # it; a dry run must not keep even that.
                transaction.set_rollback(True)
        for label, count in summary.items():
            self.stdout.write(f"  {count:>7}  {label}")
        if options["dry_run"]:
            self.stdout.write(self.style.WARNING("\nDry run: nothing changed."))
