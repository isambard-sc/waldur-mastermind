"""Media access rules for files owned by the ai_reporting app.

See :mod:`waldur_core.media.access`.
"""

from waldur_core.media import access
from waldur_mastermind.ai_reporting.models import ReportingFile

# Per-user, not per-organisation like most apps: only the person whose
# session produced the file can download it, matching the API.
access.register(
    access.upload_prefix(ReportingFile, "file"),
    access.queryset_rule(
        ReportingFile, ["file"], lambda qs, user: qs.filter(message__session__user=user)
    ),
)
