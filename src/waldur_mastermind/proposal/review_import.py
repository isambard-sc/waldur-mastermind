"""Assigning reviewers in bulk from a CSV file of proposal IDs and reviewer
emails, for calls that decide their assignments outside Waldur (distributed
peer review, where the applicants review each other's proposals in groups
worked out offline).

A row assigns the proposal whose ID (its slug) is given, in the chosen round,
to the call reviewer with the given email. A dry run reports what each row
would do; applying creates a review for every valid row, as creating one by
hand does, and reports the rest.
"""

import csv
import io

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from rest_framework import exceptions

from waldur_core.core.models import User
from waldur_core.permissions.enums import RoleEnum
from waldur_core.permissions.utils import get_user_ids

from . import models, tasks
from .enums import ProposalStates

REVIEWABLE_STATES = (ProposalStates.SUBMITTED, ProposalStates.IN_REVIEW)

# What a row came to.
CREATED = "created"
READY = "ready"  # dry run: would be created
SKIPPED = "skipped"
ERROR = "error"


def parse_rows(text: str) -> list[dict]:
    """The (proposal_id, reviewer_email) pairs of a CSV file. The columns
    are found by name, as the old HomePort importer found them: one naming
    a proposal and an ID, one naming a reviewer and an email."""
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    header = next(reader, None)
    if not header:
        raise exceptions.ValidationError({"file": "The file is empty."})
    lowered = [column.strip().lower() for column in header]

    def column(*words):
        for index, name in enumerate(lowered):
            if all(word in name for word in words):
                return index
        raise exceptions.ValidationError(
            {"file": f"No {'_'.join(words)} column was found."}
        )

    proposal_column = column("proposal", "id")
    email_column = column("reviewer", "email")
    rows = []
    for line, values in enumerate(reader, start=2):
        proposal_id = (
            values[proposal_column].strip() if len(values) > proposal_column else ""
        )
        email = values[email_column].strip() if len(values) > email_column else ""
        if proposal_id or email:
            rows.append({"line": line, "proposal_id": proposal_id, "email": email})
    return rows


def import_assignments(call, round_obj, rows, user, apply, workload_check):
    """What each row does; with ``apply``, the reviews are created.

    ``workload_check(pool_entry, count, override, user)`` refuses
    assignments above a pool reviewer's limit (views.check_reviewer_workload_limit).
    """
    proposals = {
        proposal.slug.lower(): proposal
        for proposal in models.Proposal.objects.filter(round=round_obj)
    }
    reviewer_ids = get_user_ids(
        ContentType.objects.get_for_model(models.Call),
        [call.id],
        RoleEnum.CALL_REVIEWER,
    )
    reviewers = {}
    for reviewer in User.objects.filter(id__in=reviewer_ids, is_active=True):
        reviewers.setdefault(reviewer.email.lower(), reviewer)
    live_reviews = set(
        models.Review.objects.filter(proposal__round=round_obj)
        .exclude(state=models.Review.States.REJECTED)
        .values_list("proposal_id", "reviewer_id")
    )

    results = []
    planned = []
    for row in rows:
        result = {
            "line": row["line"],
            "proposal_id": row["proposal_id"],
            "reviewer_email": row["email"],
            "proposal_name": "",
            "reviewer_name": "",
            "status": ERROR,
            "detail": "",
        }
        results.append(result)
        proposal = proposals.get(row["proposal_id"].lower())
        reviewer = reviewers.get(row["email"].lower())
        if proposal:
            result["proposal_name"] = proposal.name
        if reviewer:
            result["reviewer_name"] = reviewer.full_name or reviewer.username
        if not proposal and not reviewer:
            result["detail"] = "Proposal and reviewer not found."
        elif not proposal:
            result["detail"] = "Proposal not found in this round."
        elif not reviewer:
            result["detail"] = "No reviewer of this call has this email."
        elif proposal.state not in REVIEWABLE_STATES:
            result["detail"] = "The proposal is not submitted or in review."
        elif proposal.created_by_id == reviewer.id or proposal.has_user(reviewer):
            result["detail"] = "The reviewer is on this proposal's team."
        elif (proposal.id, reviewer.id) in live_reviews:
            result["status"] = SKIPPED
            result["detail"] = "Already assigned."
        else:
            live_reviews.add((proposal.id, reviewer.id))
            result["status"] = READY
            planned.append((result, proposal, reviewer))

    if not apply:
        return results

    with transaction.atomic():
        for result, proposal, reviewer in planned:
            pool_entry = (
                models.CallReviewerPool.objects.select_for_update(of=("self",))
                .filter(call=call, reviewer__user=reviewer)
                .first()
            )
            if pool_entry:
                try:
                    workload_check(pool_entry, 1, False, user)
                except exceptions.ValidationError as e:
                    result["status"] = ERROR
                    result["detail"] = " ".join(str(m) for m in _messages(e.detail))
                    continue
            review = models.Review.objects.create(
                proposal=proposal,
                reviewer=reviewer,
                state=models.Review.States.IN_REVIEW,
            )
            result["status"] = CREATED
            transaction.on_commit(
                lambda uuid=review.uuid: tasks.notify_reviewer_about_assignment.delay(
                    uuid
                )
            )
    return results


def _messages(detail):
    if isinstance(detail, list):
        for item in detail:
            yield from _messages(item)
    elif isinstance(detail, dict):
        for item in detail.values():
            yield from _messages(item)
    else:
        yield detail
