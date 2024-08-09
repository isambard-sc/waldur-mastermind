from datetime import timedelta

from ddt import data, ddt
from django.conf import settings
from django.core import mail
from django.test import override_settings
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import status, test

from waldur_core.core.tests.helpers import override_waldur_core_settings
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CustomerRole, ProjectRole
from waldur_core.permissions.models import Role
from waldur_core.permissions.utils import get_permissions
from waldur_core.structure.tests import factories as structure_factories
from waldur_core.users import models, tasks
from waldur_core.users.tests import factories
from waldur_core.users.utils import get_invitation_link, get_invitation_token


class BaseInvitationTest(test.APITransactionTestCase):
    def setUp(self):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)

        self.staff = structure_factories.UserFactory(is_staff=True)
        self.customer_owner = structure_factories.UserFactory()
        self.project_admin = structure_factories.UserFactory()
        self.project_manager = structure_factories.UserFactory()
        self.user = structure_factories.UserFactory()

        self.customer = structure_factories.CustomerFactory()
        self.second_customer = structure_factories.CustomerFactory()
        self.customer.add_user(self.customer_owner, CustomerRole.OWNER)

        self.extra_invitation_text = "invitation text"
        self.customer_invitation = factories.CustomerInvitationFactory(
            scope=self.customer,
            role=CustomerRole.OWNER,
            extra_invitation_text=self.extra_invitation_text,
        )

        self.project = structure_factories.ProjectFactory(customer=self.customer)
        self.project.add_user(self.project_admin, ProjectRole.ADMIN)
        self.project.add_user(self.project_manager, ProjectRole.MANAGER)

        self.project_invitation = factories.ProjectInvitationFactory(
            scope=self.project,
            role=ProjectRole.ADMIN,
        )


@ddt
class InvitationRetrieveTest(BaseInvitationTest):
    def test_unauthorized_user_can_not_list_invitations(self):
        self.project_invitation
        self.client.force_authenticate(user=self.user)
        response = self.client.get(factories.InvitationBaseFactory.get_list_url())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    @data("staff", "customer_owner")
    def test_authorized_user_can_retrieve_project_invitation(self, user):
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.get(
            factories.ProjectInvitationFactory.get_url(self.project_invitation)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        #  test list
        response = self.client.get(factories.InvitationBaseFactory.get_list_url())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_project_manager_can_retrieve_project_invitation(self):
        ProjectRole.MANAGER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=self.project_manager)
        response = self.client.get(
            factories.ProjectInvitationFactory.get_url(self.project_invitation)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        #  test list
        response = self.client.get(factories.InvitationBaseFactory.get_list_url())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(
            response.data[0]["execution_state"],
            models.Invitation.ExecutionState.SCHEDULED,
        )

    def test_unauthorized_user_cannot_retrieve_project_invitation(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.get(
            factories.ProjectInvitationFactory.get_url(self.project_invitation)
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        #  test list
        response = self.client.get(factories.InvitationBaseFactory.get_list_url())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    @data("staff", "customer_owner")
    def test_authorized_user_can_retrieve_customer_invitation(self, user):
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.get(
            factories.CustomerInvitationFactory.get_url(self.customer_invitation)
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @data("project_admin", "project_manager", "user")
    def test_unauthorized_user_cannot_retrieve_customer_invitation(self, user):
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.get(
            factories.CustomerInvitationFactory.get_url(self.customer_invitation)
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_filtering_by_customer_uuid_includes_project_invitations_for_that_customer_too(
        self,
    ):
        self.client.force_authenticate(user=self.staff)
        response = self.client.get(
            factories.InvitationBaseFactory.get_list_url(),
            {"customer_uuid": self.customer.uuid.hex},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_filtering_by_customer_url_includes_project_invitations_for_that_customer_too(
        self,
    ):
        self.client.force_authenticate(user=self.staff)
        response = self.client.get(
            factories.InvitationBaseFactory.get_list_url(),
            {"customer_uuid": self.customer.uuid.hex},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_filtering_by_another_customer_does_not_includes_project_invitations_for_initial_customer(
        self,
    ):
        other_customer = structure_factories.CustomerFactory()
        self.client.force_authenticate(user=self.staff)
        response = self.client.get(
            factories.InvitationBaseFactory.get_list_url(),
            {"customer_uuid": other_customer.uuid.hex},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)


class RetrievePendingInvitationDetailsTest(BaseInvitationTest):
    def get_details(self, user, invitation):
        self.client.force_authenticate(user=user)
        return self.client.get(
            factories.CustomerInvitationFactory.get_url(invitation, action="details")
        )

    def test_if_user_has_civil_number_only_matching_invitation_is_shown(self):
        customer_invitation = factories.CustomerInvitationFactory(
            customer=self.customer,
            role=CustomerRole.OWNER,
            civil_number="123456789",
        )
        self.user.civil_number = "123456789"
        self.user.save()
        response = self.get_details(self.user, customer_invitation)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_customer_uuid_exists_in_response(self):
        customer_invitation = factories.CustomerInvitationFactory(
            customer=self.customer,
            role=CustomerRole.OWNER,
        )
        response = self.get_details(self.user, customer_invitation)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(str(response.data["customer_uuid"]), self.customer.uuid.hex)

    def test_if_user_has_civil_number_non_matching_invitation_is_concealed(self):
        customer_invitation = factories.CustomerInvitationFactory(
            scope=self.customer,
            role=CustomerRole.OWNER,
            civil_number="123456789",
        )
        response = self.get_details(self.user, customer_invitation)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @override_waldur_core_settings(VALIDATE_INVITATION_EMAIL=True)
    def test_if_email_validation_is_enabled_matching_invitation_is_shown(
        self,
    ):
        invitation = factories.CustomerInvitationFactory(
            created_by=self.customer_owner, email=self.user.email
        )
        response = self.get_details(self.user, invitation)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @override_waldur_core_settings(VALIDATE_INVITATION_EMAIL=True)
    def test_if_email_validation_is_enabled_non_matching_invitation_is_concealed(
        self,
    ):
        invitation = factories.CustomerInvitationFactory(created_by=self.customer_owner)
        response = self.get_details(self.user, invitation)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @override_waldur_core_settings(VALIDATE_INVITATION_EMAIL=False)
    def test_if_email_validation_is_disabled_non_matching_invitation_is_shown(
        self,
    ):
        invitation = factories.CustomerInvitationFactory(created_by=self.customer_owner)
        response = self.get_details(self.user, invitation)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


@ddt
class InvitationCreateTest(BaseInvitationTest):
    @data("staff", "customer_owner")
    def test_authorized_user_can_create_project_admin_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_project_invitation_payload(
            self.project_invitation,
            role=ProjectRole.ADMIN,
        )
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    @data("staff", "customer_owner")
    def test_authorized_user_can_create_project_manager_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_project_invitation_payload(
            self.project_invitation, role=ProjectRole.MANAGER
        )
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_owner_can_create_project_manager_invitation(self):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=self.customer_owner)
        payload = self._get_valid_project_invitation_payload(
            self.project_invitation, role=ProjectRole.MANAGER
        )
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_project_admin_cannot_create_project_invitation(self):
        self.client.force_authenticate(user=self.project_admin)
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data,
            {"detail": "You do not have permission to perform this action."},
        )

    def test_unauthorized_user_cannot_create_project_invitation(self):
        self.client.force_authenticate(user=self.user)
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data("staff", "customer_owner")
    def test_authorized_user_can_create_customer_owner_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_owner_can_not_create_customer_owner_invitation(
        self,
    ):
        CustomerRole.OWNER.delete_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=self.customer_owner)
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @data("staff", "customer_owner")
    def test_user_which_created_invitation_is_stored_in_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        invitation = models.Invitation.objects.get(uuid=response.data["uuid"])
        self.assertEqual(invitation.created_by, getattr(self, user))

    @data("project_admin", "project_manager")
    def test_unauthorized_user_cannot_create_customer_owner_invitation(self, user):
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @data(
        "user",
    )
    def test_user_without_access_cannot_create_customer_owner_invitation(self, user):
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @data(
        "project_manager",
    )
    def test_user_can_create_project_invitation(self, user):
        ProjectRole.MANAGER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_user_cannot_create_project_invitation_if_he_is_manager_in_another_project(
        self,
    ):
        user = self.project_admin
        another_project = structure_factories.ProjectFactory()
        another_project.add_user(user, ProjectRole.MANAGER)
        self.client.force_authenticate(user=user)
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_user_cannot_create_invitation_without_scope(self):
        self.client.force_authenticate(user=self.staff)
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        payload.pop("scope")

        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {"scope": ["This field is required."]})

    def test_user_cannot_create_project_invitation_without_role(self):
        self.client.force_authenticate(user=self.staff)
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        payload.pop("role")

        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {"role": ["This field is required."]})

    def test_user_cannot_create_customer_invitation_without_role(self):
        self.client.force_authenticate(user=self.staff)
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        payload.pop("role")

        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {"role": ["This field is required."]})

    def test_user_can_create_invitation_for_existing_user(self):
        self.client.force_authenticate(user=self.staff)
        email = "test@example.com"
        structure_factories.UserFactory(email=email)
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        payload["email"] = email

        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    @override_waldur_core_settings(ONLY_STAFF_CAN_INVITE_USERS=True)
    def test_if_only_staff_can_create_invitation_then_owner_creates_invitation_request(
        self,
    ):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=self.customer_owner)
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        invitation = models.Invitation.objects.get(uuid=response.data["uuid"])
        self.assertEqual(invitation.state, models.Invitation.State.REQUESTED)

    @data("customer_owner", "staff")
    def test_staff_and_owner_can_pass_extra_invitation_text(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_customer_invitation_payload(self.customer_invitation)
        payload["extra_invitation_text"] = self.extra_invitation_text
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            response.data["extra_invitation_text"], self.extra_invitation_text
        )

    @data("project_manager")
    def test_manager_can_pass_extra_invitation_text(self, user):
        ProjectRole.MANAGER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        payload = self._get_valid_project_invitation_payload(self.project_invitation)
        payload["extra_invitation_text"] = self.extra_invitation_text
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url(), data=payload
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            response.data["extra_invitation_text"], self.extra_invitation_text
        )

    # Helper methods
    def _get_valid_project_invitation_payload(
        self, invitation: models.Invitation = None, role: Role = None
    ):
        invitation = invitation or factories.ProjectInvitationFactory.build()
        role = role or ProjectRole.ADMIN
        return {
            "email": invitation.email,
            "scope": structure_factories.ProjectFactory.get_url(invitation.scope),
            "role": role.uuid.hex,
        }

    def _get_valid_customer_invitation_payload(
        self, invitation: models.Invitation = None, role: Role = None
    ):
        invitation = invitation or factories.CustomerInvitationFactory.build()
        role = role or CustomerRole.OWNER
        return {
            "email": invitation.email,
            "scope": structure_factories.CustomerFactory.get_url(invitation.scope),
            "role": role.uuid.hex,
        }


@ddt
class InvitationCancelTest(BaseInvitationTest):
    @data("staff", "customer_owner", "project_manager")
    def test_authorized_user_can_cancel_project_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        ProjectRole.MANAGER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="cancel"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.project_invitation.refresh_from_db()
        self.assertEqual(
            self.project_invitation.state, models.Invitation.State.CANCELED
        )

    @data("project_admin", "user")
    def test_user_without_access_cannot_cancel_project_invitation(self, user):
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="cancel"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @data("staff", "customer_owner")
    def test_authorized_user_can_cancel_customer_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                self.customer_invitation, action="cancel"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.customer_invitation.refresh_from_db()
        self.assertEqual(
            self.customer_invitation.state, models.Invitation.State.CANCELED
        )

    def test_owner_can_not_cancel_customer_invitation(self):
        CustomerRole.OWNER.delete_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=self.customer_owner)
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                self.customer_invitation, action="cancel"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_invitation_is_canceled_after_expiration_date(self):
        event_type = "invitation_expired"
        structure_factories.NotificationFactory(key=f"users.{event_type}")
        waldur_section = settings.WALDUR_CORE.copy()
        waldur_section["INVITATION_LIFETIME"] = timedelta(weeks=1)

        with self.settings(WALDUR_CORE=waldur_section):
            invitation = factories.ProjectInvitationFactory(
                created=timezone.now() - timedelta(weeks=1),
                created_by=self.customer_owner,
            )
            tasks.cancel_expired_invitations(models.Invitation.objects.all())

        self.assertEqual(
            models.Invitation.objects.get(uuid=invitation.uuid).state,
            models.Invitation.State.EXPIRED,
        )

        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue("expired" in mail.outbox[0].subject)

    @override_settings(
        WALDUR_CORE={
            "INVITATION_LIFETIME": timedelta(weeks=1),
            "TRANSLATION_DOMAIN": "TEST",
            "HOMEPORT_URL": "TEST",
        }
    )
    def test_send_reminder_for_pending_invitations(self):
        waldur_section = settings.WALDUR_CORE.copy()
        waldur_section["INVITATION_LIFETIME"] = timedelta(weeks=1)
        event_type = "invitation_created"
        structure_factories.NotificationFactory(key=f"users.{event_type}")

        with self.settings(WALDUR_CORE=waldur_section):
            factories.ProjectInvitationFactory(
                created=timezone.now()
                - settings.WALDUR_CORE["INVITATION_LIFETIME"]
                - timedelta(days=1),
                created_by=self.customer_owner,
            )
            tasks.send_reminder_for_pending_invitations()

        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue("REMINDER" in mail.outbox[0].subject)


@ddt
class InvitationSendTest(BaseInvitationTest):
    @data("staff", "customer_owner")
    @override_settings(task_always_eager=True)
    def test_authorized_user_can_send_customer_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                self.customer_invitation, action="send"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.customer_invitation.refresh_from_db()
        self.assertEqual(
            self.customer_invitation.execution_state,
            models.Invitation.ExecutionState.OK,
        )

    @override_settings(task_always_eager=True)
    def test_invitation_email_is_rendered_correctly(self):
        event_type = "invitation_created"
        structure_factories.NotificationFactory(key=f"users.{event_type}")
        self.client.force_authenticate(user=self.staff)
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                self.customer_invitation, action="send"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(self.customer_invitation.email, mail.outbox[0].to[0])
        link = get_invitation_link(self.customer_invitation.uuid.hex)
        self.assertTrue(link in mail.outbox[0].body)
        self.assertTrue(self.extra_invitation_text in mail.outbox[0].body)

    def test_owner_can_not_send_customer_invitation(self):
        CustomerRole.OWNER.delete_permission(PermissionEnum.CREATE_CUSTOMER_PERMISSION)
        self.client.force_authenticate(user=self.customer_owner)
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                self.customer_invitation, action="send"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @data("staff", "customer_owner", "project_manager")
    def test_authorized_user_can_send_project_invitation(self, user):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        ProjectRole.MANAGER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="send"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_owner_can_send_project_invitation(self):
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_PROJECT_PERMISSION)
        self.client.force_authenticate(user=self.customer_owner)
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="send"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @data("project_admin", "user")
    def test_user_without_access_cannot_send_project_invitation(self, user):
        self.client.force_authenticate(user=getattr(self, user))
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="send"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    @freeze_time("2018-05-15")
    def test_user_can_resend_expired_invitation(self):
        customer_expired_invitation = factories.CustomerInvitationFactory(
            state=models.Invitation.State.EXPIRED
        )

        self.client.force_authenticate(user=self.staff)
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                customer_expired_invitation, action="send"
            )
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        customer_expired_invitation.refresh_from_db()
        self.assertEqual(
            customer_expired_invitation.state, models.Invitation.State.PENDING
        )
        self.assertEqual(customer_expired_invitation.created, timezone.now())


class InvitationAcceptTest(BaseInvitationTest):
    def test_authenticated_user_can_accept_project_invitation(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="accept"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.project_invitation.refresh_from_db()
        self.assertEqual(
            self.project_invitation.state, models.Invitation.State.ACCEPTED
        )
        self.assertTrue(self.project.has_user(self.user, self.project_invitation.role))

    def test_authenticated_user_can_accept_customer_invitation(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                self.customer_invitation, action="accept"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.customer_invitation.refresh_from_db()
        self.assertEqual(
            self.customer_invitation.state, models.Invitation.State.ACCEPTED
        )
        self.assertTrue(
            self.customer.has_user(self.user, self.customer_invitation.role)
        )

    def test_user_with_invalid_civil_number_cannot_accept_invitation(self):
        customer_invitation = factories.CustomerInvitationFactory(
            customer=self.customer,
            role=CustomerRole.OWNER,
            civil_number="123456789",
        )
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                customer_invitation, action="accept"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_user_which_already_has_role_within_customer_cannot_accept_invitation(self):
        customer_invitation = factories.CustomerInvitationFactory(
            scope=self.customer, role=CustomerRole.OWNER
        )
        self.client.force_authenticate(user=self.user)
        self.customer.add_user(self.user, customer_invitation.role)
        response = self.client.post(
            factories.CustomerInvitationFactory.get_url(
                customer_invitation, action="accept"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data, ["User has already the same role in this scope."]
        )

    def test_user_which_already_has_role_within_project_cannot_accept_invitation(self):
        project_invitation = factories.ProjectInvitationFactory(
            scope=self.project,
            role=ProjectRole.ADMIN,
        )
        self.client.force_authenticate(user=self.user)
        self.project.add_user(self.user, project_invitation.role)
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                project_invitation, action="accept"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data, ["User has already the same role in this scope."]
        )

    @override_waldur_core_settings(INVITATION_DISABLE_MULTIPLE_ROLES=True)
    def test_user_can_have_only_single_role_in_any_project_or_customer(self):
        self.client.force_authenticate(user=self.customer_owner)
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="accept"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, ["User already has role within another scope."])

    def test_user_which_created_invitation_is_stored_in_permission(self):
        invitation = factories.CustomerInvitationFactory(created_by=self.customer_owner)
        self.client.force_authenticate(user=self.user)
        self.client.post(
            factories.CustomerInvitationFactory.get_url(invitation, action="accept")
        )
        permission = get_permissions(invitation.customer, self.user).get()
        self.assertEqual(permission.created_by, self.customer_owner)

    def test_user_can_rewrite_his_email_on_invitation_accept(self):
        invitation = factories.CustomerInvitationFactory(
            created_by=self.customer_owner, email="invitation@i.ua"
        )
        self.client.force_authenticate(user=self.user)

        self.client.post(
            factories.CustomerInvitationFactory.get_url(invitation, action="accept"),
            {"replace_email": True},
        )

        self.assertEqual(self.user.email, invitation.email)

    @override_waldur_core_settings(VALIDATE_INVITATION_EMAIL=True)
    def test_user_can_not_rewrite_his_email_on_acceptance_if_validation_of_emails_is_on(
        self,
    ):
        invitation = factories.CustomerInvitationFactory(
            created_by=self.customer_owner, email="invitation@i.ua"
        )
        self.client.force_authenticate(user=self.user)
        url = factories.CustomerInvitationFactory.get_url(invitation, action="accept")

        response = self.client.post(url, {"replace_email": True})

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.email, invitation.email)

    @override_waldur_core_settings(VALIDATE_INVITATION_EMAIL=False)
    def test_user_can_rewrite_his_email_on_acceptance_if_validation_of_emails_is_off(
        self,
    ):
        invitation = factories.CustomerInvitationFactory(created_by=self.customer_owner)
        self.client.force_authenticate(user=self.user)
        url = factories.CustomerInvitationFactory.get_url(invitation, action="accept")

        response = self.client.post(url, {"replace_email": True})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, invitation.email)

    @override_waldur_core_settings(VALIDATE_INVITATION_EMAIL=True)
    def test_user_can_accept_invitation_if_emails_match_and_validation_of_emails_is_on(
        self,
    ):
        invitation = factories.CustomerInvitationFactory(
            created_by=self.customer_owner, email=self.user.email
        )
        self.client.force_authenticate(user=self.user)
        url = factories.CustomerInvitationFactory.get_url(invitation, action="accept")

        response = self.client.post(url, {"replace_email": True})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, invitation.email)

    @override_waldur_core_settings(ENABLE_STRICT_CHECK_ACCEPTING_INVITATION=True)
    def test_user_can_not_accept_invitation_if_emails_are_not_equal(self):
        self.client.force_authenticate(user=self.user)
        response = self.client.post(
            factories.ProjectInvitationFactory.get_url(
                self.project_invitation, action="accept"
            )
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.project_invitation.refresh_from_db()
        self.assertEqual(self.project_invitation.state, models.Invitation.State.PENDING)


class InvitationApproveTest(BaseInvitationTest):
    def test_anonymous_user_can_approve_requested_invitation(self):
        self.project_invitation.state = models.Invitation.State.REQUESTED
        self.project_invitation.save()
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url("approve"),
            {"token": get_invitation_token(self.project_invitation, self.staff)},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.project_invitation.refresh_from_db()
        self.assertEqual(self.project_invitation.state, models.Invitation.State.PENDING)

    def test_anonymous_user_can_not_approve_pending_invitation(self):
        self.project_invitation.state = models.Invitation.State.PENDING
        self.project_invitation.save()
        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url("approve"),
            {"token": get_invitation_token(self.project_invitation, self.staff)},
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class InvitationRejectTest(BaseInvitationTest):
    def test_anonymous_user_can_reject_requested_invitation(self):
        self.project_invitation.state = models.Invitation.State.REQUESTED
        self.project_invitation.save()

        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url("reject"),
            {"token": get_invitation_token(self.project_invitation, self.staff)},
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.project_invitation.refresh_from_db()
        self.assertEqual(
            self.project_invitation.state, models.Invitation.State.REJECTED
        )

    def test_anonymous_user_can_not_reject_rejected_invitation(self):
        self.project_invitation.state = models.Invitation.State.REJECTED
        self.project_invitation.save()

        response = self.client.post(
            factories.InvitationBaseFactory.get_list_url("reject"),
            {"token": get_invitation_token(self.project_invitation, self.staff)},
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
