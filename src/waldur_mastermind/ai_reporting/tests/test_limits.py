from constance.test.unittest import override_config as override_constance_config
from rest_framework import test
from rest_framework.exceptions import Throttled

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.limits import enforce_usage_limits
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession


def _message(user, *, input_tokens=0, output_tokens=0, session=None):
    session = session or ReportingSession.objects.create(user=user)
    return ReportingMessage.objects.create(
        session=session, prompt="x", status=ReportingMessage.Status.DONE,
        input_tokens=input_tokens, output_tokens=output_tokens,
    )


# Every limit used by a test below is explicitly set to -1 (unlimited) in
# ALL_UNLIMITED so each test only has the one limit it actually cares about
# switched on - the Constance defaults aren't all -1 (the global budget and
# burst cap default to real numbers), so leaving them untouched would let
# unrelated defaults leak into what's meant to be an isolated check.
ALL_UNLIMITED = {
    "AI_REPORTING_TOKEN_LIMIT_DAILY": -1,
    "AI_REPORTING_TOKEN_LIMIT_WEEKLY": -1,
    "AI_REPORTING_TOKEN_LIMIT_MONTHLY": -1,
    "AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET": -1,
    "AI_REPORTING_GLOBAL_REQUESTS_PER_MINUTE": -1,
}


class EnforceUsageLimitsTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()

    @override_constance_config(**ALL_UNLIMITED)
    def test_everything_unlimited_never_raises(self):
        _message(self.user, input_tokens=10_000_000, output_tokens=10_000_000)
        enforce_usage_limits(self.user)  # must not raise

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100})
    def test_per_user_daily_limit_blocks_once_reached(self):
        _message(self.user, input_tokens=60, output_tokens=50)  # 110 >= 100
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100})
    def test_per_user_daily_limit_allows_when_under(self):
        _message(self.user, input_tokens=10, output_tokens=10)  # 20 < 100
        enforce_usage_limits(self.user)  # must not raise

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100})
    def test_per_user_limit_does_not_count_another_users_usage(self):
        other_user = structure_factories.UserFactory()
        _message(other_user, input_tokens=1000, output_tokens=1000)
        enforce_usage_limits(self.user)  # must not raise - that usage isn't mine

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET": 100})
    def test_global_daily_budget_counts_every_users_usage(self):
        other_user = structure_factories.UserFactory()
        _message(other_user, input_tokens=60, output_tokens=50)  # 110 >= 100, not even my own usage
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_GLOBAL_REQUESTS_PER_MINUTE": 2})
    def test_burst_limit_counts_requests_not_tokens(self):
        # Zero tokens each - this limit is about request *count*, not cost.
        _message(self.user)
        _message(self.user)
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_GLOBAL_REQUESTS_PER_MINUTE": 2})
    def test_burst_limit_allows_under_the_count(self):
        _message(self.user)
        enforce_usage_limits(self.user)  # 1 < 2, must not raise

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 1})
    def test_only_recent_messages_count_toward_the_daily_window(self):
        import datetime

        from django.utils import timezone

        old_message = _message(self.user, input_tokens=1000, output_tokens=1000)
        ReportingMessage.objects.filter(pk=old_message.pk).update(
            created=timezone.now() - datetime.timedelta(days=2)
        )
        enforce_usage_limits(self.user)  # outside the 1-day window, must not raise
