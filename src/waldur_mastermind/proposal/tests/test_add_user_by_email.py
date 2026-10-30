from waldur_core.core import models as core_models
from waldur_core.core.models import User
from waldur_core.permissions.enums import PermissionEnum, RoleEnum
from waldur_core.permissions.fixtures import ProposalRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.tests.test_return_to_applicant import ReturnTestBase


class AddUserByEmailTest(ReturnTestBase):
    def setUp(self):
        super().setUp()
        # Mirrors permissions.yaml.
        ProposalRole.MANAGER.add_permission(PermissionEnum.MANAGE_PROPOSAL)
        self.proposal.state = ProposalStates.DRAFT
        self.proposal.save()
        core_models.Feature.objects.update_or_create(
            key="user.allow_user_creation", defaults={"value": True}
        )

    def add(self, email="New.Person@Example.org", user=None, role=None):
        self.client.force_authenticate(user or self.applicant)
        return self.client.post(
            self.url("add_user_by_email"),
            {
                "email": email,
                "first_name": "New",
                "last_name": "Person",
                "role": role or RoleEnum.PROPOSAL_MEMBER,
            },
        )

    def test_creates_the_account_and_adds_it(self):
        response = self.add()
        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(response.data["created"])
        user = User.objects.get(uuid=response.data["user_uuid"])
        self.assertEqual(user.username, "new.person@example.org")
        self.assertEqual(user.email, "new.person@example.org")
        self.assertEqual(user.full_name, "New Person")
        self.assertFalse(user.has_usable_password())
        self.assertTrue(self.proposal.has_user(user, ProposalRole.MEMBER))

    def test_existing_account_is_reused(self):
        existing = structure_factories.UserFactory(email="known@example.org")
        response = self.add(email="Known@example.org")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(response.data["created"])
        self.assertEqual(response.data["user_uuid"], str(existing.uuid))
        self.assertTrue(self.proposal.has_user(existing, ProposalRole.MEMBER))

    def test_refused_grant_creates_no_account(self):
        outsider = structure_factories.UserFactory()
        response = self.add(user=outsider)
        self.assertIn(response.status_code, (403, 404))
        self.assertFalse(User.objects.filter(email="new.person@example.org").exists())

        # The team is frozen once submitted: refused by the team rules.
        self.proposal.state = ProposalStates.SUBMITTED
        self.proposal.save()
        response = self.add()
        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(User.objects.filter(email="new.person@example.org").exists())

    def test_only_while_the_site_allows_user_creation(self):
        core_models.Feature.objects.filter(key="user.allow_user_creation").update(
            value=False
        )
        response = self.add()
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.filter(email="new.person@example.org").exists())
