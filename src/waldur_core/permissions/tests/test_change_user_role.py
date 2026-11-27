"""Changing a user's role is one step: the new role is checked as a grant
first, and the previous one is revoked and the new one granted together, so
the user is never without a role and a refused change leaves the role they
had. Nothing that reacts to someone leaving a project runs."""

import datetime
from unittest import mock

from constance.test import override_config
from django.db import transaction
from django.test import TestCase
from django.utils import timezone
from rest_framework import status, test
from rest_framework.exceptions import ValidationError

from waldur_core.permissions import signals, utils
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CustomerRole, ProjectRole
from waldur_core.permissions.models import UserRole
from waldur_core.structure.tests import factories


def active_roles(scope, user):
    return sorted(
        UserRole.objects.filter(scope=scope, user=user, is_active=True).values_list(
            "role__name", flat=True
        )
    )


class ChangeUserRoleTest(TestCase):
    def setUp(self):
        self.project = factories.ProjectFactory()
        self.user = factories.UserFactory()
        self.actor = factories.UserFactory()
        self.previous = utils.add_user(self.project, self.user, ProjectRole.MEMBER)

    def change(self, role, **kwargs):
        return utils.change_user_role(
            self.project,
            self.user,
            self.previous,
            role,
            changed_by=self.actor,
            **kwargs,
        )

    def test_changes_the_role(self):
        new = self.change(ProjectRole.ADMIN)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.ADMIN.name]
        )
        self.assertEqual(new.created_by, self.actor)
        self.previous.refresh_from_db()
        self.assertEqual(self.previous.revoked_by, self.actor)
        self.assertIn("Role changed from", self.previous.revoke_reason)

    def test_keeps_the_previous_expiry_unless_given(self):
        expiry = timezone.now() + datetime.timedelta(days=30)
        UserRole.objects.filter(pk=self.previous.pk).update(expiration_time=expiry)
        self.assertEqual(self.change(ProjectRole.ADMIN).expiration_time, expiry)

    def test_a_given_expiry_or_none_wins(self):
        UserRole.objects.filter(pk=self.previous.pk).update(
            expiration_time=timezone.now() + datetime.timedelta(days=30)
        )
        self.assertIsNone(
            self.change(ProjectRole.ADMIN, expiration_time=None).expiration_time
        )

    @override_config(ONLY_ONE_PROJECT_MANAGER=True)
    def test_a_refused_change_leaves_the_role_the_user_had(self):
        self.project.add_user(factories.UserFactory(), ProjectRole.MANAGER)
        with self.assertRaisesMessage(
            ValidationError, "Project already has an active project manager."
        ):
            self.change(ProjectRole.MANAGER)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.MEMBER.name]
        )

    def test_a_failure_after_the_revoke_rolls_it_back(self):
        with mock.patch.object(utils, "add_user", side_effect=RuntimeError("down")):
            with self.assertRaises(RuntimeError):
                self.change(ProjectRole.ADMIN)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.MEMBER.name]
        )

    @override_config(ONLY_ONE_PROJECT_MANAGER=True)
    def test_the_manager_can_be_moved_to_another_role(self):
        self.previous.revoke()
        self.previous = utils.add_user(self.project, self.user, ProjectRole.MANAGER)
        self.change(ProjectRole.ADMIN)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.ADMIN.name]
        )

    @override_config(INVITATION_DISABLE_MULTIPLE_ROLES=True)
    def test_one_role_per_user_does_not_block_a_change(self):
        self.change(ProjectRole.ADMIN)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.ADMIN.name]
        )

    def test_the_same_role_is_refused(self):
        with self.assertRaisesMessage(ValidationError, "already has this role"):
            self.change(ProjectRole.MEMBER)

    def test_the_user_still_has_access_when_side_effects_run(self):
        """What reacts to a revoked role is queued for when the change commits
        (offering-user deletion, for one), and then finds the user still on
        the project: nothing removes them.

        The suite's conftest runs on_commit callbacks at once; this test puts
        Django's real deferral back, as production has it."""
        seen = []

        def on_revoked(sender, instance, **kwargs):
            transaction.on_commit(
                lambda: seen.append(active_roles(self.project, self.user))
            )

        def deferred_on_commit(func, using=None, robust=False):
            transaction.get_connection(using).on_commit(func, robust=robust)

        signals.role_revoked.connect(on_revoked, dispatch_uid="test-change-role")
        self.addCleanup(
            signals.role_revoked.disconnect, dispatch_uid="test-change-role"
        )
        with mock.patch.object(transaction, "on_commit", deferred_on_commit):
            with self.captureOnCommitCallbacks(execute=True):
                self.change(ProjectRole.ADMIN)
        self.assertEqual(seen, [[ProjectRole.ADMIN.name]])


class ChangeUserRoleApiTest(test.APITransactionTestCase):
    def setUp(self):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        CustomerRole.OWNER.add_permission(PermissionEnum.DELETE_PROJECT_PERMISSION)
        CustomerRole.OWNER.add_permission(PermissionEnum.LIST_PROJECTS)
        self.owner = factories.UserFactory()
        self.project = factories.ProjectFactory()
        self.project.customer.add_user(self.owner, CustomerRole.OWNER)
        self.user = factories.UserFactory()
        self.project.add_user(self.user, ProjectRole.MEMBER)
        self.url = factories.ProjectFactory.get_url(self.project, "change_user_role")

    def post(self, actor, **data):
        self.client.force_authenticate(actor)
        return self.client.post(
            self.url,
            {
                "user": self.user.uuid.hex,
                "previous_role": ProjectRole.MEMBER.name,
                "role": ProjectRole.ADMIN.name,
                **data,
            },
            format="json",
        )

    def test_owner_changes_a_role(self):
        response = self.post(self.owner)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.ADMIN.name]
        )

    def test_needs_permission_to_revoke_as_well_as_grant(self):
        CustomerRole.OWNER.delete_permission(PermissionEnum.DELETE_PROJECT_PERMISSION)
        response = self.post(self.owner)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.MEMBER.name]
        )

    def test_a_role_the_user_does_not_hold_is_refused(self):
        response = self.post(self.owner, previous_role=ProjectRole.MANAGER.name)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("previous_role", response.data)

    def test_nobody_without_permission_may_change_roles(self):
        response = self.post(factories.UserFactory())
        self.assertIn(
            response.status_code,
            (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND),
        )
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.MEMBER.name]
        )

    @override_config(ONLY_ONE_PROJECT_MANAGER=True)
    def test_a_refused_change_keeps_the_role(self):
        self.project.add_user(factories.UserFactory(), ProjectRole.MANAGER)
        response = self.post(self.owner, role=ProjectRole.MANAGER.name)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.MEMBER.name]
        )


@override_config(DEACTIVATE_USER_IF_NO_ROLES=True)
class ChangeUserRoleKeepsTheUserActiveTest(TestCase):
    """A user whose only role is the one being changed is never left with no
    roles, so their account is not deactivated by the change."""

    def setUp(self):
        self.project = factories.ProjectFactory()
        self.user = factories.UserFactory()
        self.previous = utils.add_user(self.project, self.user, ProjectRole.MEMBER)

    def test_the_account_stays_active(self):
        utils.change_user_role(
            self.project, self.user, self.previous, ProjectRole.ADMIN
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertEqual(
            active_roles(self.project, self.user), [ProjectRole.ADMIN.name]
        )

    def test_a_user_deactivated_meanwhile_is_reactivated_by_a_new_role(self):
        """Reactivation reads the account as saved, not a copy loaded before
        it was deactivated."""
        stale = self.user
        UserRole.objects.get(pk=self.previous.pk).revoke()  # its own copy
        self.assertFalse(type(stale).all_objects.get(pk=stale.pk).is_active)
        self.assertTrue(stale.is_active)  # the copy loaded earlier

        utils.add_user(self.project, stale, ProjectRole.ADMIN)

        self.assertTrue(type(stale).all_objects.get(pk=stale.pk).is_active)
