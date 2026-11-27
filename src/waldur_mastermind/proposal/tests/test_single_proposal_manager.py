from constance.test import override_config

from waldur_core.permissions.enums import PermissionEnum, RoleEnum
from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.permissions.models import UserRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests.test_return_to_applicant import ReturnTestBase


class SingleManagerBase(ReturnTestBase):
    def setUp(self):
        super().setUp()
        # Mirrors permissions.yaml.
        ProposalRole.MANAGER.add_permission(PermissionEnum.MANAGE_PROPOSAL)
        ProposalRole.MANAGER.add_permission(PermissionEnum.UPDATE_PROPOSAL_PERMISSION)
        ProposalRole.MANAGER.add_permission(PermissionEnum.DELETE_PROPOSAL_PERMISSION)
        # A draft, as a return leaves it: no submission, no workflow.
        self.proposal.workflow_step_instances.all().delete()
        self.proposal.state = ProposalStates.DRAFT
        self.proposal.submitted_at = None
        self.proposal.save()
        self.newcomer = structure_factories.UserFactory()

    def add_manager(self):
        self.client.force_authenticate(self.applicant)
        return self.client.post(
            self.url("add_user"),
            {"user": self.newcomer.uuid.hex, "role": RoleEnum.PROPOSAL_MANAGER},
        )


class SingleProposalManagerTest(SingleManagerBase):
    def test_granting_the_manager_role_hands_the_proposal_over(self):
        self.call.single_proposal_manager = True
        self.call.save()
        response = self.add_manager()
        self.assertEqual(response.status_code, 201, response.data)
        self.proposal.refresh_from_db()
        self.assertTrue(self.proposal.has_user(self.newcomer, ProposalRole.MANAGER))
        self.assertFalse(self.proposal.has_user(self.applicant, ProposalRole.MANAGER))
        self.assertTrue(self.proposal.has_user(self.applicant, ProposalRole.ADMIN))
        self.assertEqual(self.proposal.created_by, self.newcomer)

    def test_upstream_default_allows_several_managers(self):
        response = self.add_manager()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(self.proposal.has_user(self.newcomer, ProposalRole.MANAGER))
        self.assertTrue(self.proposal.has_user(self.applicant, ProposalRole.MANAGER))
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.created_by, self.applicant)

    def test_a_team_member_can_be_handed_the_proposal(self):
        self.call.single_proposal_manager = True
        self.call.save()
        self.proposal.add_user(self.newcomer, ProposalRole.MEMBER)

        response = self.add_manager()

        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(self.proposal.has_user(self.newcomer, ProposalRole.MANAGER))
        self.assertFalse(self.proposal.has_user(self.applicant, ProposalRole.MANAGER))

    def test_only_the_new_manager_may_submit(self):
        self.call.single_proposal_manager = True
        self.call.save()
        self.add_manager()

        # The previous manager, now an administrator, is refused before any
        # check of the proposal's content.
        self.client.force_authenticate(self.applicant)
        self.assertEqual(self.client.post(self.url("submit")).status_code, 403)
        self.client.force_authenticate(self.newcomer)
        self.assertNotEqual(self.client.post(self.url("submit")).status_code, 403)

    def test_applicants_can_see_the_setting(self):
        self.call.single_proposal_manager = True
        self.call.save()
        self.client.force_authenticate(self.applicant)
        response = self.client.get(f"/api/proposal-public-calls/{self.call.uuid.hex}/")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertTrue(response.data["single_proposal_manager"])


class TransferToTeamMemberTest(SingleManagerBase):
    """Transferring management to someone already on the team changes their
    role (change_user_role) rather than adding a second one, so it works with
    one role per user (INVITATION_DISABLE_MULTIPLE_ROLES) too."""

    def setUp(self):
        super().setUp()
        self.call.single_proposal_manager = True
        self.call.save()
        self.proposal.add_user(self.newcomer, ProposalRole.ADMIN)

    def roles(self, user):
        return sorted(
            UserRole.objects.filter(
                scope=self.proposal, user=user, is_active=True
            ).values_list("role__name", flat=True)
        )

    def transfer(self):
        self.client.force_authenticate(self.applicant)
        return self.client.post(
            self.url("change_user_role"),
            {
                "user": self.newcomer.uuid.hex,
                "previous_role": RoleEnum.PROPOSAL_ADMIN,
                "role": RoleEnum.PROPOSAL_MANAGER,
            },
        )

    @override_config(INVITATION_DISABLE_MULTIPLE_ROLES=True)
    def test_adding_the_role_is_refused_with_one_role_per_user(self):
        response = self.add_manager()
        self.assertEqual(response.status_code, 400)
        self.assertIn("User already has role within this scope.", str(response.data))

    @override_config(INVITATION_DISABLE_MULTIPLE_ROLES=True)
    def test_changing_the_role_hands_the_proposal_over(self):
        response = self.transfer()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.roles(self.newcomer), [RoleEnum.PROPOSAL_MANAGER])
        self.assertEqual(self.roles(self.applicant), [RoleEnum.PROPOSAL_ADMIN])
        self.proposal.refresh_from_db()
        self.assertEqual(self.proposal.created_by, self.newcomer)

    def test_changing_the_role_works_with_several_roles_allowed_too(self):
        response = self.transfer()
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.roles(self.newcomer), [RoleEnum.PROPOSAL_MANAGER])
        self.assertEqual(self.roles(self.applicant), [RoleEnum.PROPOSAL_ADMIN])


@override_config(
    DEACTIVATE_USER_IF_NO_ROLES=True, INVITATION_DISABLE_MULTIPLE_ROLES=True
)
class TransferKeepsAccountsActiveTest(TransferToTeamMemberTest):
    """Neither the new manager nor the previous one is left, even for a
    moment, with no role: with DEACTIVATE_USER_IF_NO_ROLES, either would
    otherwise have their account deactivated and drop off the team."""

    def test_both_accounts_stay_active(self):
        UserRole.objects.filter(user__in=[self.newcomer, self.applicant]).exclude(
            object_id=self.proposal.id
        ).delete()
        response = self.transfer()
        self.assertEqual(response.status_code, 200, response.data)
        for user in (self.newcomer, self.applicant):
            user.refresh_from_db()
            self.assertTrue(user.is_active)
        self.assertEqual(self.roles(self.newcomer), [RoleEnum.PROPOSAL_MANAGER])
        self.assertEqual(self.roles(self.applicant), [RoleEnum.PROPOSAL_ADMIN])
