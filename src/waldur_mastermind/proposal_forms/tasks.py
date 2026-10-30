import logging
from datetime import timedelta

from celery import shared_task
from constance import config
from django.utils import timezone

from waldur_core.core import utils as core_utils
from waldur_core.permissions.enums import RoleEnum
from waldur_core.permissions.utils import get_users
from waldur_core.structure import models as structure_models
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
    and projects with links issued recently and still waiting."""
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
    project_ids = (
        models.FormLink.objects.filter(
            state=models.FormLink.States.ISSUED,
            created__gte=since,
            project__is_removed=False,
        )
        .values_list("project_id", flat=True)
        .distinct()
    )
    subjects = [
        *proposal_models.Proposal.objects.filter(id__in=list(proposal_ids)),
        *structure_models.Project.available_objects.filter(id__in=list(project_ids)),
    ]
    for subject in subjects:
        try:
            outcomes = responses.fetch_for_subject(subject)
        except client.FormbricksError as e:
            logger.warning("Fetching forms of %s failed: %s", subject.uuid.hex, e)
            continue
        if outcomes.get("applied"):
            logger.info(
                "Fetched %s missed form response(s) for %s.",
                outcomes["applied"],
                subject.uuid.hex,
            )


@shared_task(name="waldur_mastermind.proposal_forms.process_formbricks_deletions")
def process_formbricks_deletions():
    if not client.connection().is_configured:
        return
    responses.process_deletions()


# A project whose forms opened longer ago than this is not told: switching
# end-of-project forms on must not email the PI of every project that ended
# years ago.
NOTICE_WINDOW = timedelta(days=7)


@shared_task(name="waldur_mastermind.proposal_forms.notify_closing_forms_open")
def notify_closing_forms_open():
    """Tell the PIs of projects whose end-of-project forms opened in the last
    week, once each, that the forms are waiting for them."""
    if not client.is_available():
        return
    today = timezone.localdate()
    horizon = today + timedelta(days=responses.max_closing_open_days())
    candidates = (
        structure_models.Project.available_objects.filter(
            end_date__isnull=False,
            end_date__lte=horizon,
            end_date__gte=today - NOTICE_WINDOW - timedelta(days=1),
            closing_forms_notice__isnull=True,
        )
        .exclude(closing_form_responses__isnull=False)
        .select_related("customer")
    )
    for project in candidates:
        opens_on = responses.closing_forms_open_on(project)
        if opens_on is None or not (today - NOTICE_WINDOW <= opens_on <= today):
            continue
        managers = get_users(project, role_name=RoleEnum.PROJECT_MANAGER)
        emails = sorted({user.email for user in managers if user.email})
        models.ClosingFormsNotice.objects.create(project=project)
        if not emails:
            continue
        context = {
            "site_name": config.SITE_NAME,
            "project_name": project.name,
            "project_url": core_utils.format_homeport_link(
                "projects/{project_uuid}/", project_uuid=project.uuid.hex
            ),
            "end_date": project.end_date,
        }
        core_utils.broadcast_mail("proposal", "closing_forms_open", context, emails)
