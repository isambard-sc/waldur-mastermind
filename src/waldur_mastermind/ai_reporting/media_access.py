"""Media access rules for files owned by the ai_reporting app.

See :mod:`waldur_core.media.access`.
"""

from constance import config

from waldur_core.media import access
from waldur_mastermind.ai_reporting.models import ReportingFile
from waldur_mastermind.ai_reporting.permissions import role_denial


def _own_files(queryset, user):
    # Per-user, not per-organisation like most apps: only the person whose
    # session produced the file, and only while they may use AI reporting,
    # matching the API. Constance is read when a file is requested, not here.
    if not config.AI_REPORTING_ENABLED or role_denial(user):
        return queryset.none()
    return queryset.filter(message__session__user=user)


access.register(
    access.upload_prefix(ReportingFile, "file"),
    access.queryset_rule(ReportingFile, ["file"], _own_files),
)
