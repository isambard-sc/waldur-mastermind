from rest_framework import exceptions

from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.permissions.utils import has_user
from waldur_mastermind.proposal import permissions as proposal_permissions
from waldur_mastermind.proposal.enums import ProposalStates


def is_applicant(user, proposal) -> bool:
    """A manager or administrator on the proposal's team: those who fill in
    its forms. Staff are deliberately not included - the answers go out
    under the applicant's name and email."""
    if user is None or not user.is_authenticated or not user.is_active:
        return False
    return has_user(proposal, user, ProposalRole.MANAGER) or has_user(
        proposal, user, ProposalRole.ADMIN
    )


def can_fill_in(user, proposal) -> bool:
    return proposal.state == ProposalStates.DRAFT and is_applicant(user, proposal)


def sees_all_steps(user, proposal) -> bool:
    """Whether the user may read every step's answers, or only the steps a
    flow marks reviewer-visible: the proposal's team, those overseeing its
    call, staff and support."""
    if user.is_staff or user.is_support:
        return True
    if proposal.created_by_id == user.id or has_user(proposal, user):
        return True
    return proposal_permissions.oversees_proposal_call(user, proposal)


def is_staff_or_support_for_reads(request, view, obj=None):
    """Staff may change; support may also read."""
    user = request.user
    if user.is_staff:
        return
    if user.is_support and request.method in ("GET", "HEAD", "OPTIONS"):
        return
    raise exceptions.PermissionDenied()
