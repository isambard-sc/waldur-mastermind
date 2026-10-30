"""Answers to the forms: issuing links, taking in responses, keeping Waldur's
copy in step with Formbricks.

A form belongs to a *subject*: a proposal (its application forms, from the
call's flow) or a project (its end-of-project forms, from the closing flow
of the call that granted it). Formbricks holds the answers (the source of
truth); Waldur keeps one copy per subject and form (FormStepResponse), for
showing them. A response is matched to its subject and form only by its
single-use link id, which Waldur recorded when it issued the link
(FormLink): a webhook and a fetch go through the same apply_response, so
they cannot disagree, and application and end-of-project answers never mix.
"""

import datetime
import logging

from django.db import transaction
from django.utils import timezone

from waldur_core.structure import models as structure_models
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal.enums import ProposalStates

from . import client, flows, models

logger = logging.getLogger(__name__)


class LinkError(Exception):
    """A link cannot be issued; the message says why, for the applicant."""


def call_flow(proposal):
    try:
        return proposal.round.call.form_flow_link.flow
    except models.CallFormFlow.DoesNotExist:
        return None


# --- subjects -----------------------------------------------------------------


def is_project(subject) -> bool:
    return isinstance(subject, structure_models.Project)


def _subject_filter(subject) -> dict:
    return {"project": subject} if is_project(subject) else {"proposal": subject}


def subject_links(subject):
    return models.FormLink.objects.filter(**_subject_filter(subject))


def subject_responses(subject):
    return models.FormStepResponse.objects.filter(**_subject_filter(subject))


def project_proposal(project):
    """The proposal that created the project, through which it belongs to a
    call; None for projects no proposal created."""
    return (
        proposal_models.Proposal.objects.filter(project=project)
        .select_related("round__call")
        .order_by("-created")
        .first()
    )


def closing_setting(project):
    """Where the project's end-of-project forms come from, as
    (flow, days_before_end): the call that granted it, if that call has an
    end-of-project flow; otherwise the site's, if it applies to the
    project's organisation. None: the project has no end-of-project forms."""
    proposal = project_proposal(project)
    if proposal is not None:
        link = (
            models.CallFormFlow.objects.filter(
                call=proposal.round.call, closing_flow__isnull=False
            )
            .select_related("closing_flow")
            .first()
        )
        if link is not None:
            return link.closing_flow, link.closing_forms_open_days_before_end
    default = models.SiteClosingFormFlow.get()
    if default.applies_to(project):
        return default.flow, default.closing_forms_open_days_before_end
    return None


def closing_flow(project):
    setting = closing_setting(project)
    return setting[0] if setting else None


def flow_for(subject):
    return closing_flow(subject) if is_project(subject) else call_flow(subject)


def max_closing_open_days() -> int:
    """The most days before a project's end any end-of-project forms open."""
    days = [
        link.closing_forms_open_days_before_end
        for link in models.CallFormFlow.objects.filter(closing_flow__isnull=False)
    ]
    default = models.SiteClosingFormFlow.get()
    if default.flow_id:
        days.append(default.closing_forms_open_days_before_end)
    return max(days, default=0)


def closing_forms_open_on(project) -> datetime.date | None:
    """The day the project's end-of-project forms open: some days before its
    end date, as the call says. None if it has no end date or no such forms."""
    setting = closing_setting(project)
    if setting is None or project.end_date is None:
        return None
    return project.end_date - datetime.timedelta(days=setting[1])


def closing_forms_open(project) -> bool:
    opens_on = closing_forms_open_on(project)
    return (
        opens_on is not None
        and not project.is_removed
        and timezone.localdate() >= opens_on
    )


def subject_ids(subject) -> dict:
    """The hidden fields a link carries: IDs only, never anything personal."""
    if is_project(subject):
        proposal = project_proposal(subject)
        ids = {"project_uuid": subject.uuid.hex}
    else:
        proposal = subject
        ids = {}
    if proposal is not None:
        ids["proposal_uuid"] = proposal.uuid.hex
        ids["call_uuid"] = proposal.round.call.uuid.hex
        ids["round_uuid"] = proposal.round.uuid.hex
    return ids


# --- issuing links ------------------------------------------------------------


def _touch(proposal):
    """Work on a proposal's forms is work on the proposal: it counts as a
    change for the stale-draft clean-up. An update, so no other save logic
    runs."""
    type(proposal).objects.filter(pk=proposal.pk).update(modified=timezone.now())


def issue_link(subject, step, user) -> models.FormLink:
    """The link the applicant should use for a form now.

    An open link (handed out, not yet finished) is reused, so a form left
    half-done is resumed: Formbricks reopens the response made through it.
    Otherwise a new single-use link is minted; if the form was answered
    before, it is prefilled with the current answers (an edit).
    """
    open_link = (
        subject_links(subject)
        .filter(
            step_key=step["key"],
            survey_id=step["survey_id"],
            state=models.FormLink.States.ISSUED,
        )
        .order_by("-created")
        .first()
    )
    if open_link is not None:
        return open_link

    params = {}
    current = subject_responses(subject).filter(step_key=step["key"]).first()
    if current is not None:
        answers = current.raw_response
        if current.response_id:
            try:
                answers = client.get_response_record(current.response_id)["data"]
            except client.FormbricksError as e:
                # The answers as last received are the next best thing.
                logger.warning("Could not fetch Formbricks response to prefill: %s", e)
        params.update(client.prefill_from_answers(answers))
    params.update(subject_ids(subject))

    try:
        minted = client.mint_single_use_link(step["survey_id"])
    except client.FormbricksError as e:
        logger.error("Single-use link for survey %s failed: %s", step["survey_id"], e)
        raise LinkError(
            "The form cannot be opened just now. Please try again later, or "
            "contact the call's managers if it keeps happening."
        ) from e
    if not is_project(subject):
        _touch(subject)
    return models.FormLink.objects.create(
        single_use_id=client.single_use_id(minted),
        **_subject_filter(subject),
        step_key=step["key"],
        survey_id=step["survey_id"],
        url=client.with_params(minted, params),
        issued_to=user,
    )


# --- taking in responses ------------------------------------------------------


def _labels_for(flow, survey_id):
    schema = (flow.survey_schemas or {}).get(survey_id) or {}
    if schema.get("questions"):
        return {q["id"]: q["label"] for q in schema["questions"]}
    try:
        return client.get_survey(survey_id)
    except client.FormbricksError as e:
        # The answers matter more than their labels.
        logger.warning("Formbricks question labels not fetched: %s", e)
        return {}


def _answers(data) -> dict:
    return {k: v for k, v in (data or {}).items() if k not in client.HIDDEN_FIELD_KEYS}


def apply_response(record: dict) -> str:
    """Take in one Formbricks response (as the webhook or the Management API
    carries it). Returns what happened, for logging and tests:

    "applied", "updated" (the current answers changed in Formbricks),
    "unchanged", or why it was ignored: "unfinished", "unknown-link",
    "step-removed", "late".
    """
    if not record.get("finished"):
        # Formbricks sends updates while the applicant is still answering;
        # only a finished response is the form's answers.
        return "unfinished"
    su_id = record.get("singleUseId") or ""
    response_id = record.get("id") or ""
    if not su_id or not response_id:
        return "unknown-link"

    with transaction.atomic():
        link = (
            models.FormLink.objects.select_for_update(of=("self",))
            .select_related("proposal__round__call", "project")
            .filter(single_use_id=su_id, survey_id=record.get("surveyId"))
            .first()
        )
        if link is None:
            logger.info(
                "Formbricks response %s ignored: its link %s was not issued by "
                "Waldur for that survey.",
                response_id,
                su_id,
            )
            return "unknown-link"
        subject = link.subject
        flow = flow_for(subject)
        step = flows.get_step(flow.steps, link.step_key) if flow else None
        if step is None or step["survey_id"] != link.survey_id:
            logger.warning(
                "Formbricks response %s ignored: form %s is no longer one of "
                "%s %s's forms.",
                response_id,
                link.step_key,
                "project" if is_project(subject) else "proposal",
                subject.uuid.hex,
            )
            return "step-removed"

        current = (
            subject_responses(subject)
            .select_for_update()
            .filter(step_key=link.step_key)
            .first()
        )
        is_current = current is not None and current.response_id == response_id
        # A proposal's answers are fixed at submission; a project's stay
        # open, as its team keeps access after the end date.
        if (
            not is_project(subject)
            and subject.state != ProposalStates.DRAFT
            and not is_current
        ):
            # Answers are fixed at submission. A correction to the submitted
            # response itself (made in Formbricks) is still taken, below.
            if link.state == models.FormLink.States.ISSUED:
                link.state = models.FormLink.States.LATE
                link.response_id = response_id
                link.save(update_fields=["state", "response_id", "modified"])
            logger.warning(
                "Formbricks response %s for proposal %s arrived after submission; "
                "not applied.",
                response_id,
                subject.uuid.hex,
            )
            return "late"

        answers = _answers(record.get("data"))
        if is_current and current.raw_response == answers:
            return "unchanged"

        labels = _labels_for(flow, link.survey_id)
        previous_response_id = current.response_id if current else ""
        models.FormStepResponse.objects.update_or_create(
            **_subject_filter(subject),
            step_key=link.step_key,
            defaults={
                "survey_id": link.survey_id,
                "response_id": response_id,
                "link": link,
                "raw_response": answers,
                "question_labels": labels,
                "question_order": list(labels),
            },
        )
        link.state = models.FormLink.States.ANSWERED
        link.response_id = response_id
        link.save(update_fields=["state", "response_id", "modified"])
        if not is_project(subject) and subject.state == ProposalStates.DRAFT:
            _touch(subject)

        if previous_response_id and previous_response_id != response_id:
            # An edit: one copy of the answers in Formbricks, so the response
            # it replaced goes, now that the new one is safely here.
            subject_links(subject).filter(response_id=previous_response_id).update(
                state=models.FormLink.States.SUPERSEDED
            )
            queue_deletion(previous_response_id, "replaced by an edit")
        return "updated" if is_current else "applied"


def fetch_for_subject(subject) -> dict:
    """Bring Waldur's copy of a proposal's (or project's) answers up to date from
    Formbricks: responses to its open links, and changes to its current
    answers. For when a webhook was missed. Returns {outcome: count}."""
    outcomes = {}

    def count(outcome):
        outcomes[outcome] = outcomes.get(outcome, 0) + 1

    open_links = {}
    for link in subject_links(subject).filter(state=models.FormLink.States.ISSUED):
        open_links.setdefault(link.survey_id, set()).add(link.single_use_id)
    for survey_id, wanted in open_links.items():
        for record in client.iter_survey_responses(survey_id):
            if record.get("singleUseId") in wanted:
                count(apply_response(record))
                if record.get("finished"):
                    wanted.discard(record["singleUseId"])
            if not wanted:
                break

    for current in subject_responses(subject).exclude(response_id=""):
        try:
            record = client.get_response_record(current.response_id)
        except client.FormbricksError as e:
            logger.warning(
                "Formbricks response %s not refreshed: %s", current.response_id, e
            )
            continue
        count(apply_response(record))
    return outcomes


# --- deleting in Formbricks ---------------------------------------------------


def queue_deletion(response_id, reason):
    models.FormbricksDeletion.objects.get_or_create(
        response_id=response_id, defaults={"reason": reason}
    )


def queue_subject_deletions(subject, reason):
    """A draft proposal or a project is being deleted: its responses in
    Formbricks go too. Only responses Waldur recorded from its own links."""
    response_ids = set(
        subject_links(subject)
        .exclude(response_id="")
        .values_list("response_id", flat=True)
    ) | set(
        subject_responses(subject)
        .exclude(response_id="")
        .values_list("response_id", flat=True)
    )
    for response_id in response_ids:
        queue_deletion(response_id, reason)


MAX_DELETION_ATTEMPTS = 50


def process_deletions():
    """Delete the queued responses in Formbricks; what fails stays queued for
    the next run."""
    for deletion in models.FormbricksDeletion.objects.filter(
        attempts__lt=MAX_DELETION_ATTEMPTS
    ).order_by("created"):
        try:
            client.delete_response(deletion.response_id)
        except client.FormbricksError as e:
            deletion.attempts += 1
            deletion.last_error = str(e)[:2000]
            deletion.save(update_fields=["attempts", "last_error", "modified"])
            continue
        logger.info(
            "Formbricks response %s deleted (%s).",
            deletion.response_id,
            deletion.reason,
        )
        deletion.delete()


# --- reading answers ----------------------------------------------------------


def missing_steps(subject, flow) -> list:
    """The labels of the forms not yet answered."""
    answered = set(subject_responses(subject).values_list("step_key", flat=True))
    return [step["label"] for step in flow.steps if step["key"] not in answered]


def serialize_form_responses(subject, steps, step_keys=None) -> list:
    """Each stored form's answers as labelled questions, in the order the
    flow asks them, for reading in the proposal.

    step_keys, if given, limits which forms are included (reviewers see only
    the reviewer-visible ones). A form no longer in the flow is listed last,
    under its key.
    """
    stored = subject_responses(subject)
    if step_keys is not None:
        stored = stored.filter(step_key__in=step_keys)

    position = {step["key"]: index for index, step in enumerate(steps)}
    labels = {step["key"]: step["label"] for step in steps}
    stored = sorted(
        stored, key=lambda r: (position.get(r.step_key, len(steps)), r.step_key)
    )

    result = []
    for response in stored:
        # The answers are jsonb, which does not keep key order;
        # question_order is the order the survey asked them in.
        order = {qid: index for index, qid in enumerate(response.question_order)}
        answers = sorted(
            _answers(response.raw_response).items(),
            key=lambda pair: order.get(pair[0], len(order)),
        )
        result.append(
            {
                "step_key": response.step_key,
                "step_label": labels.get(response.step_key, response.step_key),
                "submitted_at": response.modified,
                "questions": [
                    {
                        "question_id": question_id,
                        "label": response.question_labels.get(question_id, question_id),
                        "answer": answer,
                    }
                    for question_id, answer in answers
                ],
            }
        )
    return result
