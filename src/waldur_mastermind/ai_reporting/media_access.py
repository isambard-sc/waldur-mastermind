"""Media access rules for files owned by the ai_reporting app.

See :mod:`waldur_core.media.access`.
"""

from waldur_core.media import access
from waldur_mastermind.ai_reporting.models import ReportingFile

# Ownership here is per-user (whoever's session the file was generated for),
# not the organisation-scoped customer/project rule most other apps use -
# ReportingMessageViewSet.get_queryset restricts the same way, so a download
# can't outlive what the API itself already allows.
access.register(
    access.upload_prefix(ReportingFile, "file"),
    access.queryset_rule(
        ReportingFile, ["file"], lambda qs, user: qs.filter(message__session__user=user)
    ),
)
