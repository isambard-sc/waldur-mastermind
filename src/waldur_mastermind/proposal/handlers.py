from waldur_mastermind.proposal import models


def create_reviews(sender, instance, created=False, **kwargs):
    proposal = instance

    if created:
        return

    if not proposal.tracker.has_changed('state'):
        return

    if (
        proposal.tracker.previous('state') != models.Proposal.States.DRAFT
        or proposal.state != models.Proposal.States.SUBMITTED
    ):
        return

    if (
        proposal.round.call.review_strategy
        != models.Call.ReviewStrategies.AFTER_PROPOSAL
    ):
        return

    for reviewer in proposal.round.call.callreviewer_set.all():
        models.Review.objects.create(reviewer=reviewer, proposal=proposal)