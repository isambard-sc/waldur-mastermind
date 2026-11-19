"""Organisation reports: the calls a report covers.

Only organisation_calls, ported from upstream's reports module (#1108,
9b57c79c) for the organisation statistics; upstream's full module replaces
this file when the fork merges it.
"""

from waldur_mastermind.proposal import models
from waldur_mastermind.proposal import permissions as proposal_permissions


def organisation_calls(request, manager):
    """The calls of ``manager`` that the request may report on: every one for
    staff and support, else those whose configuration it may change -- as
    call manager of the call, or call organiser of the organisation, within
    a personal access token's scopes and bindings."""
    calls = models.Call.objects.filter(manager=manager)
    if request.user.is_staff or request.user.is_support:
        return calls
    return proposal_permissions.configurable_calls(request, calls)
