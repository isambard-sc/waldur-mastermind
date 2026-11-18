"""PROJECT_MANAGER_ROLES: a site's own role (e.g. a custom "Project Lead")
counts as the project's manager wherever Waldur looks for one, including
ONLY_ONE_PROJECT_MANAGER; who may grant it is set by permissions as for any
role."""

from constance.test import override_config
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from rest_framework import test
from rest_framework.exceptions import ValidationError

from waldur_core.permissions import models, utils
from waldur_core.permissions.enums import PermissionEnum, RoleEnum
from waldur_core.permissions.fixtures import CustomerRole, ProjectRole
from waldur_core.structure.models import Project
from waldur_core.structure.tests import factories
from waldur_core.structure.tests.utils import client_add_user, client_delete_user

LEAD = "PROJECT.LEAD"


def make_lead_role():
    role = models.Role.objects.create(
        name=LEAD,
        description="Project Lead",
        content_type=ContentType.objects.get_for_model(Project),
        is_system_role=True,
    )
    for permission in (
        PermissionEnum.CREATE_PROJECT_PERMISSION,
        PermissionEnum.DELETE_PROJECT_PERMISSION,
        PermissionEnum.LIST_PROJECTS,
    ):
        role.add_permission(permission)
    return role


class ProjectManagerRolesTest(TestCase):
    def setUp(self):
        self.lead_role = make_lead_role()
        self.project = factories.ProjectFactory()
        self.lead = factories.UserFactory()
        self.project.add_user(self.lead, self.lead_role)

    def test_not_a_manager_unless_named(self):
        self.assertNotIn(
            self.lead, utils.get_users(self.project, RoleEnum.PROJECT_MANAGER)
        )
        self.assertFalse(self.project.has_user(self.lead, ProjectRole.MANAGER))

    @override_config(PROJECT_MANAGER_ROLES=[LEAD])
    def test_counts_as_the_projects_manager(self):
        self.assertIn(
            self.lead, utils.get_users(self.project, RoleEnum.PROJECT_MANAGER)
        )
        self.assertIn(self.lead, self.project.get_users(ProjectRole.MANAGER))
        self.assertIn(self.lead.email, self.project.get_user_mails(ProjectRole.MANAGER))
        self.assertTrue(self.project.has_user(self.lead, ProjectRole.MANAGER))
        ctype = ContentType.objects.get_for_model(Project)
        self.assertIn(
            self.project.id,
            list(utils.get_scope_ids(self.lead, ctype, RoleEnum.PROJECT_MANAGER)),
        )
        self.assertEqual(utils.count_active_project_managers(self.project), 1)

    @override_config(PROJECT_MANAGER_ROLES=[LEAD])
    def test_other_roles_are_unaffected(self):
        admin = factories.UserFactory()
        self.project.add_user(admin, ProjectRole.ADMIN)
        self.assertNotIn(
            self.lead, utils.get_users(self.project, RoleEnum.PROJECT_ADMIN)
        )
        self.assertFalse(self.project.has_user(admin, ProjectRole.MANAGER))

    @override_config(PROJECT_MANAGER_ROLES=[LEAD], ONLY_ONE_PROJECT_MANAGER=True)
    def test_one_lead_per_project(self):
        other = factories.UserFactory()
        for role in (self.lead_role, ProjectRole.MANAGER):
            with self.subTest(role=role.name):
                with self.assertRaisesMessage(
                    ValidationError, "Project already has an active project manager."
                ):
                    utils.validate_role_grant(self.project, other, role)
        other_project = factories.ProjectFactory(customer=self.project.customer)
        utils.validate_role_grant(other_project, other, self.lead_role)


@override_config(PROJECT_MANAGER_ROLES=[LEAD], ONLY_ONE_PROJECT_MANAGER=True)
class WhoChangesTheLeadTest(test.APITransactionTestCase):
    """The Lead invites others but cannot hand on or give up the role; the
    organisation's owners (organisation-level PROJECT.CREATE_PERMISSION /
    DELETE_PERMISSION) change who it is."""

    def setUp(self):
        self.lead_role = make_lead_role()
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        CustomerRole.OWNER.add_permission(PermissionEnum.DELETE_PROJECT_PERMISSION)
        CustomerRole.OWNER.add_permission(PermissionEnum.LIST_PROJECTS)
        ProjectRole.MEMBER.add_permission(PermissionEnum.LIST_PROJECTS)
        self.project = factories.ProjectFactory()
        self.lead = factories.UserFactory()
        self.project.add_user(self.lead, self.lead_role)
        self.owner = factories.UserFactory()
        self.project.customer.add_user(self.owner, CustomerRole.OWNER)
        self.newcomer = factories.UserFactory()

    def post(self, user, action, target, role):
        change = client_add_user if action == "add_user" else client_delete_user
        return change(self.client, user, target, self.project, role)

    def test_the_lead_adds_members(self):
        response = self.post(self.lead, "add_user", self.newcomer, ProjectRole.MEMBER)
        self.assertEqual(response.status_code, 201, response.data)

    def test_the_lead_cannot_appoint_another_lead(self):
        response = self.post(self.lead, "add_user", self.newcomer, self.lead_role)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(self.project.has_user(self.newcomer, self.lead_role))

    def test_the_lead_cannot_give_up_the_role(self):
        response = self.post(self.lead, "delete_user", self.lead, self.lead_role)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertTrue(self.project.has_user(self.lead, self.lead_role))

    def test_an_organisation_owner_changes_the_lead(self):
        self.assertEqual(
            self.post(self.owner, "delete_user", self.lead, self.lead_role).status_code,
            200,
        )
        response = self.post(self.owner, "add_user", self.newcomer, self.lead_role)
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(self.project.has_user(self.newcomer, self.lead_role))
        self.assertFalse(self.project.has_user(self.lead, self.lead_role))

    def test_a_project_member_cannot_change_the_lead(self):
        self.project.add_user(self.newcomer, ProjectRole.MEMBER)
        response = self.post(self.newcomer, "delete_user", self.lead, self.lead_role)
        self.assertEqual(response.status_code, 403, response.data)
