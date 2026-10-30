from rest_framework import exceptions

from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.permissions.utils import has_permission, has_user
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


# --- end-of-project forms -------------------------------------------------------


def can_fill_in_closing(user, project) -> bool:
    """The project's PI (its managers) and the owners of its organisation:
    those who may add people to the project. Staff too."""
    if user is None or not user.is_authenticated or not user.is_active:
        return False
    permission = PermissionEnum.CREATE_PROJECT_PERMISSION
    return has_permission(user, permission, project) or has_permission(
        user, permission, project.customer
    )


def can_read_closing(user, project, proposal) -> bool:
    """Those who fill them in, the managers of the call that granted the
    project, staff and support. Not reviewers."""
    if user.is_staff or user.is_support:
        return True
    if can_fill_in_closing(user, project):
        return True
    return proposal is not None and proposal_permissions.oversees_proposal_call(
        user, proposal
    )
