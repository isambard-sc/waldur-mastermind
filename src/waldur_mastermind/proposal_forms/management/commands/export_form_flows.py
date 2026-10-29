import yaml
from django.core.management.base import BaseCommand

from waldur_mastermind.proposal_forms import utils


class Command(BaseCommand):
    help = "Print form flows as YAML, in the format import_form_flows reads."

    def add_arguments(self, parser):
        parser.add_argument("keys", nargs="*", help="Only these flows.")

    def handle(self, *args, **options):
        self.stdout.write(
            yaml.safe_dump(
                utils.export_flows(options["keys"]),
                sort_keys=False,
                allow_unicode=True,
            )
        )
