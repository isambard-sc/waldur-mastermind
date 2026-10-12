from django.core.management.base import BaseCommand
from django.db import transaction

from waldur_openportal import utils


class Command(BaseCommand):
    help = (
        "Give every award's attachments a usage key and a true start date, so "
        "its usage can be found across every project it has been attached to."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change, and change nothing.",
        )

    def handle(self, *args, **options):
        with transaction.atomic():
            summary = utils.backfill_remote_project_attachments(
                dry_run=options["dry_run"]
            )
            if options["dry_run"]:
                transaction.set_rollback(True)
        for label, count in summary.items():
            self.stdout.write(f"  {count:>7}  {label}")
        if options["dry_run"]:
            self.stdout.write(self.style.WARNING("\nDry run: nothing changed."))
