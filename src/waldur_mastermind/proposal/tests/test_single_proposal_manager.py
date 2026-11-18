from waldur_core.permissions.enums import PermissionEnum, RoleEnum
from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests.test_return_to_applicant import ReturnTestBase


class SingleProposalManagerTest(ReturnTestBase):
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
