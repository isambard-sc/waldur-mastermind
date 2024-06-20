import logging

from celery import shared_task
from django.utils import timezone

from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal import utils

from . import log

logger = logging.getLogger(__name__)


@shared_task(
    name="waldur_mastermind.proposal.create_reviews_if_strategy_is_after_round"
)
def create_reviews_if_strategy_is_after_round():
    rounds = proposal_models.Round.objects.filter(
        start_time__lte=timezone.now(),
        cutoff_time__gte=timezone.now(),
        call__state=proposal_models.Call.States.ACTIVE,
        review_strategy=proposal_models.Round.ReviewStrategies.AFTER_ROUND,
    )

    for r in rounds:
        utils.create_reviews_of_round(r)


@shared_task(
    name="waldur_mastermind.proposal.create_reviews_if_strategy_is_after_proposal"
)
def create_reviews_if_strategy_is_after_proposal():
    rounds = proposal_models.Round.objects.filter(
        call__state=proposal_models.Call.States.ACTIVE,
        review_strategy=proposal_models.Round.ReviewStrategies.AFTER_PROPOSAL,
    )

    for r in rounds:
        for proposal in r.proposal_set.filter(
            state__in=(
                proposal_models.Proposal.States.SUBMITTED,
                proposal_models.Proposal.States.IN_REVIEW,
            )
        ):
            utils.process_proposals_pending_reviewers(proposal)


@shared_task(
    name="waldur_mastermind.proposal.proposals_for_ended_rounds_should_be_cancelled"
)
def proposals_for_ended_rounds_should_be_cancelled():
    for proposal in proposal_models.Proposal.objects.exclude(
        state__in=(
            proposal_models.Proposal.States.ACCEPTED,
            proposal_models.Proposal.States.REJECTED,
            proposal_models.Proposal.States.CANCELED,
        )
    ).filter(round__cutoff_time__lt=timezone.now()):
        proposal.state = proposal_models.Proposal.States.CANCELED
        proposal.save(update_fields=["state"])

        log.event_logger.proposal.info(
            f"Proposal {proposal.name} has been canceled.",
            event_type="proposal_canceled",
            event_context={"proposal": proposal},
        )
        logger.info(f"Proposal {proposal.name} has been canceled.")
