"""Seeding the award ID counters past every award already issued.

Without this, a fresh ProposalIDGenerator starts at zero and the first new
proposal of the year is given the award ID of the first old one. The generator
skips IDs it can see on live proposals and projects, but not ones that now live
only in the archive, nor ones issued to drafts since deleted -- which only the
fork's own counter remembers.
"""

from io import StringIO

from django.core.management import call_command
from django.db import connection
from django.test import TestCase

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import award_ids
from waldur_mastermind.proposal import models as proposal_models

from . import factories


def counter(year):
    generator = proposal_models.ProposalIDGenerator.objects.filter(year=year).first()
    return generator.count if generator else 0


class SeedTest(TestCase):
    def seed(self, **kwargs):
        out = StringIO()
        call_command("seed_award_id_generator", stdout=out, **kwargs)
        return out.getvalue()

    def old_counter(self, **years):
        with connection.cursor() as cursor:
            cursor.execute(
                "CREATE TABLE old_proposal_proposalidgenerator "
                "(id serial PRIMARY KEY, year integer UNIQUE, count integer)"
            )
            for year, count in years.items():
                cursor.execute(
                    "INSERT INTO old_proposal_proposalidgenerator (year, count) "
                    "VALUES (%s, %s)",
                    [int(year.lstrip("y")), count],
                )

    def test_the_counter_is_raised_to_the_old_one(self):
        self.old_counter(y2026=900)
        self.seed()
        self.assertEqual(counter(2026), 900)

    def test_the_old_counter_wins_over_what_survives_in_the_data(self):
        """Deleted drafts consumed numbers that now appear nowhere else."""
        self.old_counter(y2026=900)
        factories.ArchivedProposalFactory(slug=award_ids.format_award_id(500, 2026))
        self.seed()
        self.assertEqual(counter(2026), 900)

    def test_the_data_wins_when_it_is_ahead_of_the_old_counter(self):
        """In case the counter row was lost or reset."""
        self.old_counter(y2026=10)
        factories.ArchivedProposalFactory(slug=award_ids.format_award_id(640, 2026))
        self.seed()
        self.assertEqual(counter(2026), 640)

    def test_it_works_from_the_archive_alone(self):
        factories.ArchivedProposalFactory(slug=award_ids.format_award_id(820, 2025))
        self.seed()
        self.assertEqual(counter(2025), 820)

    def test_award_ids_on_live_projects_count(self):
        structure_factories.ProjectFactory(slug=award_ids.format_award_id(77, 2026))
        self.seed()
        self.assertEqual(counter(2026), 77)

    def test_slugs_that_are_not_award_ids_are_ignored(self):
        factories.ArchivedProposalFactory(slug="ROUND-001")
        self.assertIn("nothing to seed", self.seed())

    def test_a_counter_is_never_lowered(self):
        """Safe to re-run after the counter has moved on."""
        proposal_models.ProposalIDGenerator.objects.create(year=2026, count=1000)
        self.old_counter(y2026=900)
        self.seed()
        self.assertEqual(counter(2026), 1000)

    def test_a_dry_run_changes_nothing(self):
        self.old_counter(y2026=900)
        self.assertIn("Dry run", self.seed(dry_run=True))
        self.assertEqual(counter(2026), 0)

    def test_once_seeded_the_next_award_id_is_past_every_old_one(self):
        """The point of the exercise, end to end."""
        self.old_counter(y2026=900)
        self.seed()
        issued = proposal_models.ProposalIDGenerator.issue_award_id(2026)
        self.assertEqual(award_ids.parse_award_id(issued)[1], 901)
