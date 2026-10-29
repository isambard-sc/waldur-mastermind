import yaml
from django.core.management.base import BaseCommand, CommandError

from waldur_mastermind.proposal_forms import utils


class Command(BaseCommand):
    help = (
        "Create or update form flows from a YAML file, by key. The steps are "
        "checked as the API checks them."
    )

    def add_arguments(self, parser):
        parser.add_argument("path", help="YAML file with a 'flows' list.")
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change, and change nothing.",
        )

    def handle(self, *args, **options):
        try:
            with open(options["path"], encoding="utf-8") as f:
                document = yaml.safe_load(f)
            results = utils.import_flows(document, dry_run=options["dry_run"])
        except (OSError, yaml.YAMLError, utils.FlowImportError) as e:
            raise CommandError(str(e))
        for key, action in results:
            self.stdout.write(f"  {action:>9}  {key}")
        if options["dry_run"]:
            self.stdout.write(self.style.WARNING("\nDry run: nothing changed."))
