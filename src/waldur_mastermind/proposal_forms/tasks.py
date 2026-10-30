import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal.enums import ProposalStates

from . import client, models, responses

logger = logging.getLogger(__name__)

# How far back the periodic fetch looks for links still waiting for their
# response: a form is usually finished the day it is opened.
OPEN_LINK_WINDOW = timedelta(days=14)


@shared_task(name="waldur_mastermind.proposal_forms.fetch_open_form_responses")
def fetch_open_form_responses():
    """Pick up responses whose webhook never arrived: for draft proposals
    with links issued recently and still waiting."""
    if not client.is_available():
        return
    since = timezone.now() - OPEN_LINK_WINDOW
    proposal_ids = (
        models.FormLink.objects.filter(
            state=models.FormLink.States.ISSUED,
            created__gte=since,
            proposal__state=ProposalStates.DRAFT,
        )
        .values_list("proposal_id", flat=True)
        .distinct()
    )
    for proposal in proposal_models.Proposal.objects.filter(id__in=list(proposal_ids)):
        try:
            outcomes = responses.fetch_for_proposal(proposal)
        except client.FormbricksError as e:
            logger.warning(
                "Fetching forms of proposal %s failed: %s", proposal.uuid.hex, e
            )
            continue
        if outcomes.get("applied"):
            logger.info(
                "Fetched %s missed form response(s) for proposal %s.",
                outcomes["applied"],
                proposal.uuid.hex,
            )


@shared_task(name="waldur_mastermind.proposal_forms.process_formbricks_deletions")
def process_formbricks_deletions():
    if not client.connection().is_configured:
        return
    responses.process_deletions()
