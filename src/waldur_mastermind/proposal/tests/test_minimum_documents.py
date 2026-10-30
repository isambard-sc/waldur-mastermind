from django.test import TestCase
from rest_framework import exceptions

from waldur_mastermind.proposal import models
from waldur_mastermind.proposal.tests import factories
from waldur_mastermind.proposal.views import (
    ProposalViewSet,
    validate_documents_present,
)


class MinimumDocumentsTest(TestCase):
    def setUp(self):
        self.proposal = factories.ProposalFactory()
        self.call = self.proposal.round.call

    def attach(self):
        models.ProposalDocumentation.objects.create(proposal=self.proposal)

    def test_upstream_default_requires_none(self):
        validate_documents_present(self.proposal)
        self.assertEqual(self.proposal.documents_missing(), 0)

    def test_submission_waits_for_the_minimum(self):
        self.call.minimum_number_of_documents = 2
        self.call.save()
        self.attach()
        with self.assertRaises(exceptions.ValidationError) as raised:
            validate_documents_present(self.proposal)
        self.assertIn("at least 2 supporting documents", str(raised.exception.detail))
        can_submit, reason = self.proposal.can_submit()
        self.assertFalse(can_submit)
        self.assertIn("at least 2", str(reason))

        self.attach()
        validate_documents_present(self.proposal)

    def test_checked_at_submission(self):
        self.assertIn(validate_documents_present, ProposalViewSet.submit_validators)
