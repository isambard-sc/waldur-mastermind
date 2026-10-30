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
        self.proposal.state = ProposalStates.DRAFT
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
