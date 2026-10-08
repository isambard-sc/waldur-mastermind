"""Bring the award ID counters up past every award already issued.

A new ``ProposalIDGenerator`` starts at zero. On a site that issued award IDs
before the resync, that is not a fresh start but a collision waiting to happen:
the first new proposal of the year would be given the award ID of the first
old one. ``issue_award_id()`` skips any ID it can see on a live proposal or
project, but it cannot see an ID that now lives only in the archive, or one
that was issued to a draft since deleted.

So for each year this raises the counter to the higher of

* the fork's own counter, from ``old_proposal_proposalidgenerator``. This is
  the authoritative record: it counted every ID ever issued, including those
  given to unsubmitted proposals that were later auto-deleted and appear
  nowhere else; and
* the highest sequence decodable from any award ID in the archive, or on a
  live proposal or project -- in case the counter row was lost or reset.

It only ever raises a counter, never lowers one, so it is safe to re-run and
safe against a counter that has already moved on. Run it before switching on
``proposal.auto_assign_award_id``.

Lives in the archive app rather than the proposal app because it knows about
the fork's old tables, which have no business in code meant for upstream.
"""

from collections import defaultdict

from django.core.management.base import BaseCommand
from django.db import connection, transaction

from waldur_core.structure import models as structure_models
from waldur_mastermind.proposal import award_ids
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal_archive import models, utils


def old_counters():
    """``{year: count}`` from the fork's generator, if its table survives."""
    if not utils.table_exists("old_proposal_proposalidgenerator"):
        return {}
    with connection.cursor() as cursor:
        cursor.execute('SELECT year, count FROM "old_proposal_proposalidgenerator"')
        return {year: count for year, count in cursor.fetchall()}


def highest_in_use():
    """``{year: highest sequence}`` across every award ID anyone holds."""
    slugs = [
        models.ArchivedProposal.objects.values_list("slug", flat=True),
        proposal_models.Proposal.objects.values_list("slug", flat=True),
        # objects, not available_objects: a deleted project's ID stays issued.
        structure_models.Project.objects.values_list("slug", flat=True),
    ]
    highest = defaultdict(int)
    for queryset in slugs:
        for slug in queryset.iterator():
            try:
                year, sequence, _version = award_ids.parse_award_id(slug)
            except ValueError:
                continue
            highest[year] = max(highest[year], sequence)
    return highest


class Command(BaseCommand):
    help = "Raise the award ID counters above every award ID already issued."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would change, and change nothing.",
        )

    def handle(self, *args, **options):
        old = old_counters()
        seen = highest_in_use()
        years = sorted(set(old) | set(seen))
        if not years:
            self.stdout.write("No award IDs anywhere: nothing to seed.")
            return

        self.stdout.write(
            f"  {'year':<6} {'old counter':>12} {'highest seen':>13} "
            f"{'current':>9} {'new':>9}"
        )
        with transaction.atomic():
            for year in years:
                target = max(old.get(year, 0), seen.get(year, 0))
                generator, _created = (
                    proposal_models.ProposalIDGenerator.objects.select_for_update().get_or_create(
                        year=year
                    )
                )
                current = generator.count
                if target > current:
                    new = target
                    if not options["dry_run"]:
                        generator.count = target
                        generator.save(update_fields=["count"])
                else:
                    new = current
                marker = "" if new == current else "  <- raised"
                self.stdout.write(
                    f"  {year:<6} {old.get(year, '-'):>12} {seen.get(year, '-'):>13} "
                    f"{current:>9} {new:>9}{marker}"
                )
            if options["dry_run"]:
                transaction.set_rollback(True)
                self.stdout.write(self.style.WARNING("\nDry run: nothing changed."))
