from constance import config
from rest_framework import exceptions


def check_enabled_roles(request, view, obj=None):
    """Checks AI_REPORTING_ENABLED_ROLES, read on every request so a change
    takes effect immediately. Same idea as the chat app's
    AI_ASSISTANT_ENABLED_ROLES, minus the anonymous mode."""
    enabled_roles = config.AI_REPORTING_ENABLED_ROLES
    user = request.user

    if enabled_roles == "disabled":
        raise exceptions.PermissionDenied("AI reporting is not available.")
    elif enabled_roles == "staff":
        if not user.is_staff:
            raise exceptions.PermissionDenied(
                "AI reporting is currently available to staff users only."
            )
    elif enabled_roles == "staff_and_support":
        if not (user.is_staff or user.is_support):
            raise exceptions.PermissionDenied(
                "AI reporting is currently available to staff and support users only."
            )
    elif enabled_roles != "all":
        raise exceptions.PermissionDenied(
            "AI reporting access is not configured correctly."
        )


def is_staff_or_support_for_reads(request, view, obj=None):
    """Staff may change the harness connection; support may only read it."""
    user = request.user
    if user.is_staff:
        return
    if user.is_support and request.method in ("GET", "HEAD", "OPTIONS"):
        return
    raise exceptions.PermissionDenied()
