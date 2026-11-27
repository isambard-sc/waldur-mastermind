"""Media access rules for files owned by the ai_reporting app.

See :mod:`waldur_core.media.access`.
"""

from constance import config

from waldur_core.media import access
from waldur_core.permissions.utils import check_pat_support_scope
from waldur_mastermind.ai_reporting.models import ReportingFile
from waldur_mastermind.ai_reporting.permissions import role_denial


def _own_files(queryset, request_or_user):
    # Per-user, not per-organisation like most apps: only the person whose
    # session produced the file, and only while they may use AI reporting,
    # matching the API. Constance is read when a file is requested, not here.
    user = getattr(request_or_user, "user", request_or_user)
    if user is not request_or_user and not check_pat_support_scope(request_or_user):
        # An access token needs the support or staff scope, as on the API.
        return queryset.none()
    if not config.AI_REPORTING_ENABLED or role_denial(user):
        return queryset.none()
    return queryset.filter(message__session__user=user)


access.register(
    access.upload_prefix(ReportingFile, "file"),
    access.queryset_rule(ReportingFile, ["file"], _own_files),
    # A personal access token's scopes are on the request.
    with_request=True,
)
