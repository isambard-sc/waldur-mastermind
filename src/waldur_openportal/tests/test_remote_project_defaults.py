"""A new remote project (an award from a call, or one made by hand by
attaching a remote OpenPortal resource to a project) starts locked to the
domains of the project's members at the time it is created."""

from django.test import TestCase

from waldur_core.permissions.fixtures import ProjectRole
from waldur_core.structure.tests import factories as structure_factories
from waldur_openportal import models, remote_project_service

DESTINATION = "airr.brics.isambard-ai"


class NewRemoteProjectDefaultsTest(TestCase):
    def setUp(self):
        self.project = structure_factories.ProjectFactory()
        self.settings = structure_factories.ServiceSettingsFactory(
            customer=self.project.customer
        )
        self.number = 0

    def member(self, email, role=None):
        user = structure_factories.UserFactory(email=email)
        self.project.add_user(user, role or ProjectRole.MEMBER)
        return user

    def create(self, remote_identifier=None):
        self.number += 1
        allocation = models.RemoteAllocation.objects.create(
            name=f"award {self.number}",
            project=self.project,
            service_settings=self.settings,
            backend_id=f"airr-gw_{self.number}.airr",
        )
        return remote_project_service.get_or_create_remote_project(
            allocation, DESTINATION, remote_identifier=remote_identifier
        )

    def test_locked_to_the_members_domains(self):
        self.member("pi@bristol.ac.uk", ProjectRole.MANAGER)
        self.member("someone@ox.ac.uk")
        self.member("collaborator@gmail.com")

        remote_project = self.create()

        self.assertEqual(
            remote_project.membership_control,
            models.MembershipControlChoices.LOCKED,
        )
        self.assertEqual(
            remote_project.allowed_domains,
            [
                "*.bristol.ac.uk",
                "*.ox.ac.uk",
                "bristol.ac.uk",
                "collaborator@gmail.com",
                "ox.ac.uk",
            ],
        )

    def test_approved_path_has_the_same_defaults(self):
        self.member("pi@bristol.ac.uk", ProjectRole.MANAGER)
        remote_project = self.create(remote_identifier="u6aa.brics")
        self.assertEqual(
            remote_project.membership_control,
            models.MembershipControlChoices.LOCKED,
        )
        self.assertEqual(
            remote_project.allowed_domains, ["*.bristol.ac.uk", "bristol.ac.uk"]
        )

    def test_no_members_means_nothing_allowed(self):
        remote_project = self.create()
        self.assertEqual(
            remote_project.membership_control,
            models.MembershipControlChoices.LOCKED,
        )
        # [] is "nothing allowed"; None would be "no restriction".
        self.assertEqual(remote_project.allowed_domains, [])

    def test_fixed_at_creation(self):
        self.member("pi@bristol.ac.uk", ProjectRole.MANAGER)
        remote_project = self.create()
        self.member("late@cam.ac.uk")

        again = remote_project_service.get_or_create_remote_project(
            remote_project.remote_allocation, DESTINATION
        )

        self.assertEqual(again.pk, remote_project.pk)
        self.assertEqual(again.allowed_domains, ["*.bristol.ac.uk", "bristol.ac.uk"])

    def test_an_owners_choice_is_kept(self):
        remote_project = self.create()
        remote_project.membership_control = models.MembershipControlChoices.OPEN
        remote_project.allowed_domains = None
        remote_project.save()

        again = remote_project_service.get_or_create_remote_project(
            remote_project.remote_allocation, DESTINATION
        )

        self.assertEqual(again.membership_control, models.MembershipControlChoices.OPEN)
        self.assertIsNone(again.allowed_domains)
