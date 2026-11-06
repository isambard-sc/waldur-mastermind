from constance import config
from rest_framework import exceptions


def check_enabled_roles(request, view, obj=None):
    """Mirrors waldur_mastermind.chat.views.LLMConfigurationMixin's own
    AI_ASSISTANT_ENABLED_ROLES check - reads AI_REPORTING_ENABLED_ROLES fresh
    on every request (not cached at import time), so changing the Constance
    value takes effect immediately, with no redeploy and no restart.

    No "anonymous" branch, unlike the chat app's equivalent: ai_reporting has
    no anonymous/unauthenticated mode at all - IsAuthenticated is already a
    base permission_class on the viewset, so request.user is always a real
    user here.
    """
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
        raise exceptions.PermissionDenied("AI reporting access is not configured correctly.")


def is_staff_or_support_for_reads(request, view, obj=None):
    """Staff may change the harness connection; support may only read it.

    Same split as proposal_forms.permissions.is_staff_or_support_for_reads
    for the Formbricks connection - not reused directly, since that function
    belongs to a different, unrelated app."""
    user = request.user
    if user.is_staff:
        return
    if user.is_support and request.method in ("GET", "HEAD", "OPTIONS"):
        return
    raise exceptions.PermissionDenied()
