import datetime

from constance.test.unittest import override_config as override_constance_config
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import test
from rest_framework.exceptions import Throttled

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.limits import (
    enforce_concurrency_limit,
    enforce_usage_limits,
)
from waldur_mastermind.ai_reporting.models import (
    ReportingMessage,
    ReportingSession,
    ReportingUsageRecord,
)


def _message(
    user,
    *,
    input_tokens=0,
    output_tokens=0,
    cache_read_tokens=0,
    cache_write_tokens=0,
    session=None,
):
    """Creates the message and the usage record, like ask_harness does."""
    session = session or ReportingSession.objects.create(user=user)
    message = ReportingMessage.objects.create(
        session=session,
        prompt="x",
        status=ReportingMessage.Status.DONE,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )
    ReportingUsageRecord.objects.create(
        user=user,
        status=ReportingUsageRecord.Status.DONE,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_tokens=cache_read_tokens,
        cache_write_tokens=cache_write_tokens,
    )
    return message


# Turn every limit off, so each test only switches on the one it checks.
ALL_UNLIMITED = {
    "AI_REPORTING_TOKEN_LIMIT_DAILY": -1,
    "AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET": -1,
}


class EnforceUsageLimitsTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()

    @override_constance_config(**ALL_UNLIMITED)
    def test_everything_unlimited_never_raises(self):
        _message(self.user, input_tokens=10_000_000, output_tokens=10_000_000)
        enforce_usage_limits(self.user)  # must not raise

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100}
    )
    def test_per_user_daily_limit_blocks_once_reached(self):
        _message(self.user, input_tokens=60, output_tokens=50)  # 110 >= 100
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100}
    )
    def test_per_user_daily_limit_allows_when_under(self):
        _message(self.user, input_tokens=10, output_tokens=10)  # 20 < 100
        enforce_usage_limits(self.user)  # must not raise

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100}
    )
    def test_per_user_limit_does_not_count_another_users_usage(self):
        other_user = structure_factories.UserFactory()
        _message(other_user, input_tokens=1000, output_tokens=1000)
        enforce_usage_limits(self.user)  # must not raise - that usage isn't mine

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100}
    )
    def test_per_user_limit_counts_cache_tokens(self):
        # Most input is cached, so leaving cache out would barely count it.
        _message(
            self.user,
            input_tokens=5,
            output_tokens=5,
            cache_read_tokens=60,
            cache_write_tokens=30,
        )  # 100 >= 100
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET": 100}
    )
    def test_global_budget_counts_cache_tokens(self):
        _message(self.user, cache_read_tokens=100)
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET": 100}
    )
    def test_global_daily_budget_counts_every_users_usage(self):
        other_user = structure_factories.UserFactory()
        _message(
            other_user, input_tokens=60, output_tokens=50
        )  # 110 >= 100, not even my own usage
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @override_constance_config(**{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 1})
    def test_only_recent_messages_count_toward_the_daily_window(self):
        _message(self.user, input_tokens=1000, output_tokens=1000)
        # The token check reads usage records, so age that row.
        ReportingUsageRecord.objects.filter(user=self.user).update(
            created=timezone.now() - datetime.timedelta(days=2)
        )
        enforce_usage_limits(self.user)  # outside the 1-day window, must not raise

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100}
    )
    def test_limit_still_applies_after_the_message_itself_is_deleted(self):
        # Deleting the message must not reset the limit.
        message = _message(self.user, input_tokens=60, output_tokens=50)  # 110 >= 100
        message.delete()
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)

    @freeze_time("2026-11-13 12:00:00")
    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET": 100}
    )
    def test_global_budget_resets_at_midnight(self):
        # 13 hours ago is within a rolling 24h, but it was yesterday.
        _message(self.user, input_tokens=60, output_tokens=50)
        ReportingUsageRecord.objects.update(
            created=datetime.datetime(2026, 11, 12, 23, 0, tzinfo=datetime.UTC)
        )
        enforce_usage_limits(self.user)  # must not raise

    @freeze_time("2026-11-13 22:00:00")
    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET": 100}
    )
    def test_global_budget_retry_time_is_next_midnight(self):
        _message(self.user, input_tokens=60, output_tokens=50)
        with self.assertRaises(Throttled) as raised:
            enforce_usage_limits(self.user)
        self.assertEqual(raised.exception.wait, 2 * 60 * 60)


class LargeTotalsTest(test.APITestCase):
    """Totals above the integer column limit must not break the check."""

    def setUp(self):
        self.user = structure_factories.UserFactory()

    @override_constance_config(
        **{**ALL_UNLIMITED, "AI_REPORTING_TOKEN_LIMIT_DAILY": 100}
    )
    def test_columns_near_the_integer_limit_still_add_up(self):
        big = 2**31 - 1
        _message(
            self.user,
            input_tokens=big,
            output_tokens=big,
            cache_read_tokens=big,
            cache_write_tokens=big,
        )
        with self.assertRaises(Throttled):
            enforce_usage_limits(self.user)


@override_constance_config(**ALL_UNLIMITED)
class ConcurrentQuestionsLimitTest(test.APITestCase):
    def setUp(self):
        self.user = structure_factories.UserFactory()
        others = structure_factories.UserFactory.create_batch(2)
        for other in others:
            ReportingMessage.objects.create(
                session=ReportingSession.objects.create(user=other), prompt="x"
            )

    @override_constance_config(AI_REPORTING_MAX_CONCURRENT_QUESTIONS=2)
    def test_blocks_once_that_many_questions_are_running(self):
        with self.assertRaises(Throttled):
            enforce_concurrency_limit()

    @override_constance_config(AI_REPORTING_MAX_CONCURRENT_QUESTIONS=3)
    def test_allows_while_under(self):
        enforce_concurrency_limit()  # must not raise

    @override_constance_config(AI_REPORTING_MAX_CONCURRENT_QUESTIONS=-1)
    def test_there_is_no_unlimited(self):
        with self.assertRaises(Throttled):
            enforce_concurrency_limit()

    @override_constance_config(AI_REPORTING_MAX_CONCURRENT_QUESTIONS=2)
    def test_finished_questions_do_not_count(self):
        ReportingMessage.objects.update(status=ReportingMessage.Status.DONE)
        enforce_concurrency_limit()  # must not raise
