from constance.test.unittest import override_config as override_constance_config
from rest_framework import test
from rest_framework.exceptions import PermissionDenied

from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.ai_reporting.permissions import check_enabled_roles


class _Request:
    def __init__(self, user):
        self.user = user


class CheckEnabledRolesTest(test.APITestCase):
    def setUp(self):
        self.staff = structure_factories.UserFactory(is_staff=True)
        self.support = structure_factories.UserFactory(is_support=True)
        self.regular = structure_factories.UserFactory()

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="disabled")
    def test_disabled_blocks_everyone(self):
        for user in (self.staff, self.support, self.regular):
            with self.assertRaises(PermissionDenied):
                check_enabled_roles(_Request(user), view=None)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="staff")
    def test_staff_only_allows_just_staff(self):
        check_enabled_roles(_Request(self.staff), view=None)  # must not raise
        with self.assertRaises(PermissionDenied):
            check_enabled_roles(_Request(self.support), view=None)
        with self.assertRaises(PermissionDenied):
            check_enabled_roles(_Request(self.regular), view=None)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="staff_and_support")
    def test_staff_and_support_excludes_regular_users(self):
        check_enabled_roles(_Request(self.staff), view=None)  # must not raise
        check_enabled_roles(_Request(self.support), view=None)  # must not raise
        with self.assertRaises(PermissionDenied):
            check_enabled_roles(_Request(self.regular), view=None)

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="all")
    def test_all_allows_everyone(self):
        for user in (self.staff, self.support, self.regular):
            check_enabled_roles(_Request(user), view=None)  # must not raise

    @override_constance_config(AI_REPORTING_ENABLED_ROLES="something-unexpected")
    def test_unrecognised_value_fails_closed(self):
        """A typo in the setting must deny access, not allow everyone."""
        with self.assertRaises(PermissionDenied):
            check_enabled_roles(_Request(self.staff), view=None)
