"""Award IDs: format, counter, when they are issued, and the project they reach.

The format is pinned against IDs the fork's own code produced, not against its
docstring -- the docstring's examples were wrong (``0251-4788-8877-1`` for
sequence 0, where the code produced ``...8873-1``), and matching the docstring
would have made every new award ID disagree with every old one.
"""

import logging
import re
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from waldur_core.core import models as core_models
from waldur_core.core.features import FEATURES
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal import award_ids, models, utils
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests import factories, fixtures

THIS_YEAR = timezone.now().year


def set_features(award_id=False, application_portal=False):
    for key, value in (
        (award_ids.AWARD_ID_FEATURE, award_id),
        (core_models.APPLICATION_PORTAL_FEATURE, application_portal),
    ):
        core_models.Feature.objects.update_or_create(key=key, defaults={"value": value})


class FormatTest(SimpleTestCase):
    """Byte-identical to the fork's generator, which people's IDs came from."""

    def test_ids_match_what_the_old_code_actually_produced(self):
        self.assertEqual(award_ids.format_award_id(0, 2025), "0251-4788-8873-1")
        self.assertEqual(award_ids.format_award_id(1, 2025), "0251-7531-9061-1")

    def test_a_real_award_id_round_trips(self):
        self.assertEqual(award_ids.format_award_id(820, 2025), "0251-4064-4677-1")
        self.assertEqual(award_ids.parse_award_id("0251-4064-4677-1"), (2025, 820, 1))

    def test_the_version_is_the_follow_on_number(self):
        self.assertEqual(
            award_ids.parse_award_id(award_ids.format_award_id(820, 2025, 4)),
            (2025, 820, 4),
        )

    def test_a_corrupted_digit_fails_the_check(self):
        with self.assertRaises(ValueError):
            award_ids.parse_award_id("0251-4064-4678-1")

    def test_an_upstream_slug_is_not_an_award_id(self):
        self.assertFalse(award_ids.is_award_id("ROUND-001"))
        self.assertFalse(award_ids.is_award_id(""))
        self.assertFalse(award_ids.is_award_id(None))

    def test_the_right_shape_is_not_enough(self):
        """Shape alone would decode an arbitrary slug into a bogus sequence."""
        self.assertFalse(award_ids.is_award_id("1234-5678-9012-3"))

    def test_the_example_shown_to_administrators_is_a_valid_award_id(self):
        """The feature description is generated into HomePort and shown to
        admins. An example that fails its own check digit would be worse than
        none -- the first draft of this one did."""
        description = next(
            item["description"]
            for section in FEATURES
            if section["key"] == "proposal"
            for item in section["items"]
            if item["key"] == "auto_assign_award_id"
        )
        examples = re.findall(r"\d{4}-\d{4}-\d{4}-\d+", description)
        self.assertTrue(examples)
        for example in examples:
            self.assertTrue(award_ids.is_award_id(example), example)

    def test_the_sequence_range_is_enforced(self):
        with self.assertRaises(ValueError):
            award_ids.format_award_id(award_ids.MAX_SEQUENCE + 1, 2026)


class CounterTest(TestCase):
    def test_the_first_sequence_of_a_year_is_one(self):
        self.assertEqual(models.ProposalIDGenerator.next_sequence(2030), 1)
        self.assertEqual(models.ProposalIDGenerator.next_sequence(2030), 2)

    def test_each_year_counts_on_its_own(self):
        models.ProposalIDGenerator.next_sequence(2030)
        self.assertEqual(models.ProposalIDGenerator.next_sequence(2031), 1)

    def test_an_exhausted_year_fails_rather_than_wrapping(self):
        """Wrapping to zero would re-issue the year's first awards."""
        models.ProposalIDGenerator.objects.create(
            year=2030, count=award_ids.MAX_SEQUENCE
        )
        with self.assertRaises(RuntimeError):
            models.ProposalIDGenerator.next_sequence(2030)

    def test_an_id_already_on_a_project_is_skipped(self):
        """An unseeded counter must not hand out a real award's ID."""
        structure_factories.ProjectFactory(slug=award_ids.format_award_id(1, THIS_YEAR))
        self.assertEqual(
            models.ProposalIDGenerator.issue_award_id(),
            award_ids.format_award_id(2, THIS_YEAR),
        )

    def test_an_id_on_a_deleted_project_is_skipped_too(self):
        project = structure_factories.ProjectFactory(
            slug=award_ids.format_award_id(1, THIS_YEAR)
        )
        project.delete()  # soft
        self.assertEqual(
            models.ProposalIDGenerator.issue_award_id(),
            award_ids.format_award_id(2, THIS_YEAR),
        )

    def test_an_id_already_on_a_proposal_is_skipped(self):
        factories.ProposalFactory(slug=award_ids.format_award_id(1, THIS_YEAR))
        self.assertEqual(
            models.ProposalIDGenerator.issue_award_id(),
            award_ids.format_award_id(2, THIS_YEAR),
        )

    def test_it_gives_up_loudly_rather_than_looping_forever(self):
        taken = award_ids.format_award_id(1, THIS_YEAR)
        structure_factories.ProjectFactory(slug=taken)
        with mock.patch.object(award_ids, "format_award_id", return_value=taken):
            with self.assertRaises(RuntimeError):
                models.ProposalIDGenerator.issue_award_id()


class AssignmentTest(TestCase):
    """Both flags, not one -- see award_ids.is_enabled()."""

    def test_with_both_flags_a_new_proposal_gets_an_award_id(self):
        set_features(award_id=True, application_portal=True)
        proposal = factories.ProposalFactory()
        self.assertEqual(award_ids.parse_award_id(proposal.slug)[0], THIS_YEAR)

    def test_without_either_flag_it_gets_the_ordinary_slug(self):
        proposal = factories.ProposalFactory()
        self.assertFalse(award_ids.is_award_id(proposal.slug))

    def test_the_award_flag_alone_does_nothing(self):
        """Otherwise the project's award ID could be overwritten later."""
        set_features(award_id=True, application_portal=False)
        proposal = factories.ProposalFactory()
        self.assertFalse(award_ids.is_award_id(proposal.slug))

    def test_the_award_flag_alone_says_why_it_is_doing_nothing(self):
        set_features(award_id=True, application_portal=False)
        with self.assertLogs(award_ids.logger, level=logging.WARNING) as logs:
            factories.ProposalFactory()
        self.assertIn("application_portal_only", logs.output[0])

    def test_the_application_portal_flag_alone_does_nothing(self):
        set_features(award_id=False, application_portal=True)
        self.assertFalse(award_ids.is_award_id(factories.ProposalFactory().slug))

    def test_an_explicit_slug_is_kept(self):
        set_features(award_id=True, application_portal=True)
        self.assertEqual(factories.ProposalFactory(slug="CHOSEN").slug, "CHOSEN")

    def test_turning_the_flag_on_does_not_rewrite_existing_proposals(self):
        proposal = factories.ProposalFactory()
        original = proposal.slug
        set_features(award_id=True, application_portal=True)
        proposal.name = "renamed"
        proposal.save()
        proposal.refresh_from_db()
        self.assertEqual(proposal.slug, original)

    def test_consecutive_proposals_get_consecutive_award_ids(self):
        """Distinct is not enough on its own -- upstream's slugs are distinct
        too. They must be award IDs, drawn from successive sequence numbers."""
        set_features(award_id=True, application_portal=True)
        slugs = [factories.ProposalFactory().slug for _ in range(5)]
        sequences = [award_ids.parse_award_id(slug)[1] for slug in slugs]
        self.assertEqual(sequences, [1, 2, 3, 4, 5])


class AllocationTest(TestCase):
    """The project created on acceptance carries the award ID, exactly."""

    def accepted_project(self):
        fixture = fixtures.ProposalFixture()
        proposal = fixture.proposal
        proposal.state = ProposalStates.IN_REVIEW
        proposal.project = None
        proposal.save()
        utils.allocate_proposal(proposal, approved_by=fixture.staff)
        proposal.refresh_from_db()
        return proposal, proposal.project

    def test_the_project_slug_is_the_award_id(self):
        set_features(award_id=True, application_portal=True)
        proposal, project = self.accepted_project()
        self.assertTrue(award_ids.is_award_id(proposal.slug))
        self.assertEqual(project.slug, proposal.slug)

    def test_the_award_id_never_goes_through_generate_slug(self):
        """generate_slug's "-N" suffix is the same syntax as a follow-on.

        A project named like an existing slug would come back as "<slug>-1"
        from generate_slug, indistinguishable from a real follow-on award.
        """
        set_features(award_id=True, application_portal=True)
        with mock.patch.object(
            structure_factories.ProjectFactory._meta.model,
            "generate_slug",
            side_effect=AssertionError("generate_slug must not be called"),
        ):
            proposal, project = self.accepted_project()
        self.assertEqual(project.slug, proposal.slug)

    def test_without_the_flags_the_project_gets_an_ordinary_slug(self):
        proposal, project = self.accepted_project()
        self.assertFalse(award_ids.is_award_id(project.slug))

    def test_a_proposal_from_before_the_flag_does_not_lend_its_slug(self):
        """Only a real award ID is carried; an upstream slug is not."""
        fixture = fixtures.ProposalFixture()
        proposal = fixture.proposal  # created with the flags off
        proposal.state = ProposalStates.IN_REVIEW
        proposal.project = None
        proposal.save()
        set_features(award_id=True, application_portal=True)
        utils.allocate_proposal(proposal, approved_by=fixture.staff)
        proposal.refresh_from_db()
        self.assertNotEqual(proposal.project.slug, proposal.slug)
