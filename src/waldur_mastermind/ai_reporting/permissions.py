from constance import config
from rest_framework import exceptions

from waldur_core.permissions.utils import check_pat_support_scope


def role_denial(user) -> str | None:
    """Why this user may not use AI reporting under AI_REPORTING_ENABLED_ROLES,
    or None if they may. Read on every call so a change takes effect at once.
    Same idea as the chat app's AI_ASSISTANT_ENABLED_ROLES, minus the
    anonymous mode."""
    enabled_roles = config.AI_REPORTING_ENABLED_ROLES
    if enabled_roles == "disabled":
        return "AI reporting is not available."
    if enabled_roles == "staff":
        if not user.is_staff:
            return "AI reporting is currently available to staff users only."
        return None
    if enabled_roles == "staff_and_support":
        if not (user.is_staff or user.is_support):
            return (
                "AI reporting is currently available to staff and support users only."
            )
        return None
    # No "all users" option: the harness reads Waldur as a support account,
    # so any user could ask it about anything.
    return "AI reporting access is not configured correctly."


def check_support_scope(request, view, obj=None):
    """An access token needs the support (or staff) scope: the harness reads
    all of Waldur, so a narrowly scoped token must not reach it."""
    if not check_pat_support_scope(request):
        raise exceptions.PermissionDenied(
            "This access token does not have the support or staff scope."
        )


def check_enabled_roles(request, view, obj=None):
    denial = role_denial(request.user)
    if denial:
        raise exceptions.PermissionDenied(denial)
    check_support_scope(request, view, obj)
