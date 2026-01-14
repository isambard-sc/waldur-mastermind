import logging
from datetime import datetime, timedelta
from typing import cast

from django.db import transaction
from django.db.models import OuterRef

from waldur_core.core.utils import SubqueryCount, get_system_robot
from waldur_core.permissions.utils import get_users
from waldur_core.structure import models as structure_models
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal import tasks
from waldur_mastermind.proposal.enums import (
    ProposalStates,
    RequestedOfferingStates,
)

logger = logging.getLogger(__name__)


def _scramble_sequence_number(n: int) -> int:
    """
    Scramble a sequence number using Linear Congruential Generator (LCG).

    This creates a bijective (one-to-one) mapping that makes sequential
    numbers appear random while remaining deterministic and reversible.
    Maps integers from 0-9999999 to other integers in the same range.

    Uses LCG parameters chosen for good distribution over 7-digit range:
    - Modulus: 10000000 (our range)
    - Multiplier: 2743019 (coprime with modulus)
    - Increment: 4788887 (odd number for full period)

    Args:
        n: Sequence number from 0 to 9999999

    Returns:
        Scrambled sequence number from 0 to 9999999

    Example:
        >>> _scramble_sequence_number(0)
        4788887
        >>> _scramble_sequence_number(1)
        7531906
        >>> _scramble_sequence_number(2)
        274925
    """
    # LCG parameters for 10 million range
    modulus = 10000000  # Our range (0-9999999)
    multiplier = 2743019  # Carefully chosen for good distribution
    increment = 4788887  # Odd number ensures full period

    # Apply LCG formula: (a * n + c) mod m
    scrambled = (multiplier * n + increment) % modulus
    return scrambled


def _unscramble_sequence_number(scrambled: int) -> int:
    """
    Reverse the scrambling to get original sequence number.

    This inverts the LCG transformation using modular multiplicative inverse.
    Useful for debugging or verification.

    Args:
        scrambled: Scrambled sequence number from 0 to 9999999

    Returns:
        Original sequence number from 0 to 9999999

    Example:
        >>> _unscramble_sequence_number(4788887)
        0
        >>> _unscramble_sequence_number(7531906)
        1
    """
    modulus = 10000000
    multiplier = 2743019
    increment = 4788887

    # Calculate modular multiplicative inverse of multiplier
    # Using extended Euclidean algorithm
    inv_multiplier = pow(multiplier, -1, modulus)

    # Reverse LCG: n = (scrambled - c) * a^(-1) mod m
    original = (inv_multiplier * (scrambled - increment)) % modulus
    return original


def generate_proposal_id(
    sequence_number: int,
    proposal_version: int = 1,
    year: int | None = None,
    scramble: bool = True,
) -> str:
    """
    Generate a unique proposal ID in the format: YYYV-NNNN-NNNNC-V

    Format breakdown:
    - YYY: Last 3 digits of the year (e.g., 025 for 2025)
    - V: Scheme version (always 1)
    - NNNN-NNNN: 7-digit sequence number with hyphen separator (0000-000 to 9999-999)
    - C: Checksum digit (0-9) calculated using Luhn algorithm
    - V: Proposal version (1, 2, 3, etc.)

    The sequence number is scrambled using LCG to avoid revealing
    sequential patterns (0, 1, 2, etc.). This is reversible and bijective.

    Args:
        sequence_number: Integer from 0 to 9999999 representing the proposal sequence
        proposal_version: Version of this proposal (defaults to 1, minimum 1)
        year: Year to use (defaults to current year)
        scramble: Whether to scramble the sequence number (default True)

    Returns:
        Formatted proposal ID string (e.g., "0251-4788-8877-1")

    Raises:
        ValueError: If sequence_number is out of range or proposal_version is less than 1

    Example:
        >>> generate_proposal_id(0, proposal_version=1)
        '0251-4788-8877-1'  # Scrambled from 0 -> 4788887
        >>> generate_proposal_id(1, proposal_version=1)
        '0251-7531-9069-1'  # Scrambled from 1 -> 7531906
    """
    # Validate inputs
    if not 0 <= sequence_number <= 9999999:
        raise ValueError("sequence_number must be between 0 and 9999999")

    if proposal_version < 1:
        raise ValueError("proposal_version must be at least 1")

    # Use current year if not provided
    if year is None:
        year = datetime.now().year

    # Extract last 3 digits of year
    year_suffix = year % 1000  # e.g., 2025 -> 25, then we'll format as 025

    # Scheme version is always 1
    scheme_version = 1

    # Scramble the sequence number to avoid obvious patterns
    if scramble:
        display_sequence = _scramble_sequence_number(sequence_number)
    else:
        display_sequence = sequence_number

    # Format the sequence number as 7 digits with hyphen: NNNN-NNN
    sequence_str = f"{display_sequence:07d}"
    sequence_formatted = f"{sequence_str[:4]}-{sequence_str[4:]}"

    # Calculate checksum using Luhn algorithm on the digits
    # Combine year, scheme version, and sequence number for checksum calculation
    checksum_input = f"{year_suffix:03d}{scheme_version}{sequence_str}"
    checksum = _calculate_luhn_checksum(checksum_input)

    # Build the final ID
    proposal_id = f"{year_suffix:03d}{scheme_version}-{sequence_formatted}{checksum}-{proposal_version}"

    return proposal_id


def _calculate_luhn_checksum(digits: str) -> int:
    """
    Calculate Luhn checksum digit for the given string of digits.

    The Luhn algorithm is a checksum formula used to validate identification numbers.
    It works by:
    1. Starting from the rightmost digit, double every second digit
    2. If doubling results in a two-digit number, subtract 9
    3. Sum all digits
    4. The checksum is (10 - (sum % 10)) % 10

    Args:
        digits: String of digits to calculate checksum for

    Returns:
        Single digit checksum (0-9)

    Example:
        >>> _calculate_luhn_checksum("0251234567")
        8
    """

    def luhn_double(digit: int) -> int:
        """Double a digit and subtract 9 if result is >= 10."""
        doubled = digit * 2
        return doubled - 9 if doubled >= 10 else doubled

    # Convert string to list of integers
    digit_list = [int(d) for d in digits]

    # Process from right to left, doubling every second digit
    total = 0
    for i, digit in enumerate(reversed(digit_list)):
        if i % 2 == 1:  # Every second digit from the right
            total += luhn_double(digit)
        else:
            total += digit

    # Calculate checksum
    checksum = (10 - (total % 10)) % 10
    return checksum


def migrate_proposal_and_project_ids():
    """
    Migrate existing proposals to use new ID format and sync project slugs.

    This function:
    1. Finds all proposals without the new ID format
    2. Generates unique IDs for them using ProposalIDGenerator
    3. If proposal is accepted and has a project, copies slug to project

    Safe to run multiple times - only processes proposals without new format.

    Returns:
        Dict with counts of proposals and projects updated
    """
    from waldur_mastermind.proposal.models import Proposal, ProposalIDGenerator

    # Regex pattern to match new ID format: YYYV-NNNN-NNNNC-V
    # Example: 0251-4788-8877-1
    import re

    new_id_pattern = re.compile(r"^\d{4}-\d{4}-\d{4}-\d+$")

    proposals_updated = 0
    projects_updated = 0
    errors = []

    # Get all proposals
    all_proposals = Proposal.objects.all().order_by("created")

    logger.info(f"Starting migration of {all_proposals.count()} proposals")

    for proposal in all_proposals:
        try:
            # Check if proposal already has new format
            if proposal.slug and new_id_pattern.match(proposal.slug):
                # Already has new format - check if project needs updating
                if proposal.project and proposal.project.slug != proposal.slug:
                    old_project_slug = proposal.project.slug
                    proposal.project.slug = proposal.slug
                    proposal.project.save(update_fields=["slug"])
                    projects_updated += 1
                    logger.info(
                        f"Updated project {proposal.project.id} slug: "
                        f"{old_project_slug} -> {proposal.slug}"
                    )
                continue

            # Proposal needs new ID - get year from creation date
            year = proposal.created.year

            # Get or create generator for this year
            generator, created = ProposalIDGenerator.objects.get_or_create(year=year)

            if created:
                logger.info(f"Created ProposalIDGenerator for year {year}")

            # Generate new ID with retry logic
            max_retries = 100
            new_slug = None

            for attempt in range(max_retries):
                sequence_number = generator.increment_count()
                proposal_id = generate_proposal_id(
                    sequence_number, proposal_version=1, year=year
                )

                # Check uniqueness
                if (
                    not Proposal.objects.filter(slug=proposal_id)
                    .exclude(pk=proposal.pk)
                    .exists()
                ):
                    new_slug = proposal_id
                    break

            if not new_slug:
                error_msg = (
                    f"Failed to generate unique ID for proposal "
                    f"{proposal.pk} after {max_retries} attempts"
                )
                logger.error(error_msg)
                errors.append(error_msg)
                continue

            # Update proposal slug using queryset update to avoid triggering save()
            # and updating the modified timestamp
            old_slug = proposal.slug
            Proposal.objects.filter(pk=proposal.pk).update(slug=new_slug)
            proposals_updated += 1

            logger.info(
                f"Updated proposal {proposal.pk} slug: {old_slug} -> {new_slug}"
            )

            # If proposal has a project, update project slug too
            if proposal.project:
                old_project_slug = proposal.project.slug
                proposal.project.slug = new_slug
                proposal.project.save(update_fields=["slug"])
                projects_updated += 1
                logger.info(
                    f"Updated project {proposal.project.id} slug: "
                    f"{old_project_slug} -> {new_slug}"
                )

        except Exception as e:
            error_msg = f"Error migrating proposal {proposal.pk}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)

    result = {
        "proposals_processed": all_proposals.count(),
        "proposals_updated": proposals_updated,
        "projects_updated": projects_updated,
        "errors": errors,
    }

    logger.info(
        f"Migration complete: {proposals_updated} proposals updated, "
        f"{projects_updated} projects updated, {len(errors)} errors"
    )

    return result


def get_available_reviewer(proposal: proposal_models.Proposal):
    reviewer_ids = proposal.review_set.values_list("reviewer_id", flat=True)
    reviews = proposal_models.Review.objects.filter(
        reviewer_id=OuterRef("pk"), proposal__round__call=proposal.round.call
    ).exclude(state=proposal_models.Review.States.REJECTED)
    available_reviewer = (
        proposal.round.call.reviewers.exclude(id__in=reviewer_ids)
        .annotate(reviewers_count=SubqueryCount(reviews))
        .order_by("reviewers_count")
    )
    number_of_needed_reviewers = max(
        0,
        proposal.round.minimum_number_of_reviewers
        or 0
        - proposal.review_set.exclude(
            state=proposal_models.Review.States.REJECTED
        ).count(),
    )
    return available_reviewer[:number_of_needed_reviewers]


def process_proposals_pending_reviewers(proposal: proposal_models.Proposal):
    logger.warning(f"Skipping processing proposal {proposal.uuid} for reviewers")
    return proposal

    for reviewer in get_available_reviewer(proposal):
        proposal_models.Review.objects.create(reviewer=reviewer, proposal=proposal)

    # Only update state and send notification if the state is actually changing
    if proposal.state != ProposalStates.IN_REVIEW:
        old_state = proposal.state
        proposal.state = ProposalStates.IN_REVIEW
        tasks.notify_user_about_proposal_state_update.delay(
            proposal.uuid, old_state, proposal.state
        )
        return proposal.save()
    return proposal


def allocate_proposal(proposal: proposal_models.Proposal):
    proposal_round = proposal.round
    name = proposal.name
    start_date = None
    end_date = None
    call_prefix = proposal_round.call.backend_id or proposal_round.call.slug
    project_name = " - ".join(
        [call_prefix, proposal_round.start_time.strftime("%Y-%m-%d"), name]
    )[: structure_models.PROJECT_NAME_LENGTH]

    if (
        proposal.round.allocation_time
        == proposal_models.Round.AllocationTimes.FIXED_DATE
    ):
        start_date = proposal.round.allocation_date
    else:
        # today is the start date
        start_date = datetime.today().date()

    # Calculate end_date based on duration_in_days and start_date
    # Priority: call.fixed_duration_in_days > proposal.duration_in_days
    duration_in_days = None
    if proposal_round.call.fixed_duration_in_days:
        duration_in_days = proposal_round.call.fixed_duration_in_days
    elif proposal.duration_in_days:
        duration_in_days = proposal.duration_in_days

    if duration_in_days and start_date:
        end_date = start_date + timedelta(days=duration_in_days)

    # need to create a unique short name for the project
    short_name = f"{call_prefix}_{proposal.uuid}".replace(" ", "").lower()

    # Remove everything except lower-case letters, digits, underscores, hyphens
    short_name = "".join(c for c in short_name if c.isalnum() or c in ("_", "-"))

    if len(short_name) > 50:
        short_name = short_name[:50]

    logger.info(f"Start date for project {project_name} is {start_date}.")
    logger.info(f"End date for project {project_name} is {end_date}.")
    logger.info(f"Duration in days is {duration_in_days}.")
    logger.info(
        f"Copying slug '{proposal.slug}' from proposal to project "
        f"for consistent tracking."
    )

    project = structure_models.Project.objects.create(
        customer=proposal_round.call.manager.customer,
        name=project_name,
        description=proposal.project_summary,
        start_date=start_date,
        end_date=end_date,
        short_name=short_name,
        slug=proposal.slug,  # Copy slug from proposal for consistent tracking ID
    )
    project = cast(structure_models.Project, project)

    if start_date:
        logger.info(
            f"Field start_date of {project} has been changed to "
            f"{proposal.round.allocation_date}."
        )

    if end_date:
        logger.info(
            f"Field end_date of {project} has been set to {end_date} "
            f"based on duration of {duration_in_days} days."
        )

    proposal.project = project
    proposal.save()

    requested_resources = proposal.requestedresource_set.filter(
        requested_offering__state=RequestedOfferingStates.ACCEPTED
    )

    for mapping in proposal.round.call.proposalprojectrolemapping_set.all():  # type: ignore
        users = get_users(proposal, mapping.proposal_role)
        for user in users:
            if mapping.project_role:
                project.add_user(user, mapping.project_role)
            else:
                continue

    for requested_resource in requested_resources:
        with transaction.atomic():
            if "name" not in requested_resource.attributes:
                requested_resource.attributes["name"] = str(
                    requested_resource.requested_offering.offering.name
                )

            attrs = dict(
                project=project,
                offering=requested_resource.requested_offering.offering,
                plan=requested_resource.requested_offering.plan,
                attributes=requested_resource.attributes,
                limits=requested_resource.limits,
            )
            resource = marketplace_models.Resource(
                **attrs,
                name=project.name,
            )
            resource.init_cost()
            resource.save()

            order = marketplace_models.Order(
                **attrs,
                resource=resource,
                created_by=get_system_robot(),
            )
            order.init_cost()
            order.save()

            requested_resource.resource = resource
            requested_resource.save()


def cancel_draft_proposals_in_round(call_round: proposal_models.Round):
    """Cancel all draft proposals in a round that has ended."""
    call_round.proposal_set.filter(state=ProposalStates.DRAFT).update(
        state=ProposalStates.CANCELED
    )


def create_reviews_for_submitted_proposals(call_round: proposal_models.Round):
    """Create reviews for submitted/in-review proposals in a round."""
    for proposal in call_round.proposal_set.filter(
        state__in=(
            ProposalStates.SUBMITTED,
            ProposalStates.IN_REVIEW,
        )
    ):
        process_proposals_pending_reviewers(proposal)


def process_closed_round(call_round: proposal_models.Round):
    """Process a closed round: cancel draft proposals and create reviews for submitted ones."""
    cancel_draft_proposals_in_round(call_round)
    create_reviews_for_submitted_proposals(call_round)


def get_proposal_review_counts(proposal: proposal_models.Proposal) -> dict:
    base_queryset = proposal_models.Review.objects.filter(proposal=proposal)

    submitted_reviews = base_queryset.filter(
        state=proposal_models.Review.States.SUBMITTED
    ).count()

    rejected_reviews = base_queryset.filter(
        state=proposal_models.Review.States.REJECTED
    ).count()

    pending_reviews = base_queryset.filter(
        state__in=[
            proposal_models.Review.States.CREATED,
            proposal_models.Review.States.IN_REVIEW,
        ]
    ).count()

    return {
        "submitted_reviews": submitted_reviews,
        "rejected_reviews": rejected_reviews,
        "pending_reviews": pending_reviews,
    }


def fix_submitted_at_field():
    """Fix submitted_at field for proposals in submitted or later states."""
    from waldur_mastermind.proposal.models import Proposal

    proposals_to_fix = Proposal.objects.filter(
        state__in=[
            ProposalStates.SUBMITTED,
            ProposalStates.IN_REVIEW,
            ProposalStates.ACCEPTED,
            ProposalStates.REJECTED,
            ProposalStates.CANCELED,
        ],
        submitted_at__isnull=True,
    )

    for proposal in proposals_to_fix:
        # Set submitted_at to last modified time if available, else to created time
        proposal.submitted_at = proposal.modified or proposal.created
        proposal.save(update_fields=["submitted_at"])
        logger.info(
            f"Set submitted_at for proposal {proposal} to {proposal.submitted_at}."
        )

    logger.info(f"Fixed submitted_at field for {proposals_to_fix.count()} proposal(s).")
