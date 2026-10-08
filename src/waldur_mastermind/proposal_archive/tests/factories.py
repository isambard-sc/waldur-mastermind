import factory
from django.utils import timezone

from waldur_mastermind.proposal_archive import models


class ArchivedCallFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = models.ArchivedCall

    name = factory.Sequence(lambda n: f"Call {n}")
    state = "archived"


class ArchivedRoundFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = models.ArchivedRound

    call = factory.SubFactory(ArchivedCallFactory)
    start_time = factory.LazyFunction(timezone.now)


class ArchivedProposalFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = models.ArchivedProposal

    round = factory.SubFactory(ArchivedRoundFactory)
    call = factory.LazyAttribute(lambda proposal: proposal.round.call)
    name = factory.Sequence(lambda n: f"Proposal {n}")
    state = "accepted"


class ArchivedReviewFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = models.ArchivedReview

    proposal = factory.SubFactory(ArchivedProposalFactory)
    state = "submitted"
    summary_private_comment = "candid"


class ArchivedMembershipFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = models.ArchivedMembership

    scope_kind = models.ArchivedMembership.Scopes.PROPOSAL
    proposal = factory.SubFactory(ArchivedProposalFactory)
    call = factory.LazyAttribute(lambda membership: membership.proposal.call)
    role_name = "PROPOSAL.MANAGER"
