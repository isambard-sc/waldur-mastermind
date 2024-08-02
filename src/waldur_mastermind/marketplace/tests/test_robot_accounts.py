from ddt import data, ddt
from rest_framework import status, test

from waldur_core.core.models import get_ssh_key_fingerprints
from waldur_core.permissions.enums import PermissionEnum
from waldur_core.permissions.fixtures import CustomerRole
from waldur_mastermind.marketplace.tests import factories, fixtures


@ddt
class RobotAccountTest(test.APITransactionTestCase):
    def setUp(self):
        self.fixture = fixtures.MarketplaceFixture()
        CustomerRole.OWNER.add_permission(PermissionEnum.CREATE_RESOURCE_ROBOT_ACCOUNT)
        CustomerRole.OWNER.add_permission(PermissionEnum.UPDATE_RESOURCE_ROBOT_ACCOUNT)
        CustomerRole.OWNER.add_permission(PermissionEnum.DELETE_RESOURCE_ROBOT_ACCOUNT)

        CustomerRole.MANAGER.add_permission(
            PermissionEnum.CREATE_RESOURCE_ROBOT_ACCOUNT
        )
        CustomerRole.MANAGER.add_permission(
            PermissionEnum.UPDATE_RESOURCE_ROBOT_ACCOUNT
        )
        CustomerRole.MANAGER.add_permission(
            PermissionEnum.DELETE_RESOURCE_ROBOT_ACCOUNT
        )

    @data("staff", "service_manager", "service_owner")
    def test_authorized_user_can_create_robot_account(self, user):
        self.client.force_authenticate(getattr(self.fixture, user))
        url = factories.RobotAccountFactory.get_list_url()
        resource_url = factories.ResourceFactory.get_url(self.fixture.resource)
        response = self.client.post(url, {"resource": resource_url, "type": "cicd"})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)

    @data("user", "customer_support", "admin", "manager")
    def test_unauthorized_user_can_not_create_robot_account(self, user):
        self.client.force_authenticate(getattr(self.fixture, user))
        url = factories.RobotAccountFactory.get_list_url()
        resource_url = factories.ResourceFactory.get_url(self.fixture.resource)
        response = self.client.post(url, {"resource": resource_url, "type": "cicd"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @data(
        "staff",
        "service_manager",
        "service_owner",
        "customer_support",
        "admin",
        "manager",
    )
    def test_authorized_user_can_get_robot_account(self, user):
        self.client.force_authenticate(getattr(self.fixture, user))
        account = factories.RobotAccountFactory(resource=self.fixture.resource)
        url = factories.RobotAccountFactory.get_url(account)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

    @data("staff", "service_manager", "service_owner")
    def test_authorized_user_can_update_robot_account(self, user):
        self.client.force_authenticate(getattr(self.fixture, user))
        account = factories.RobotAccountFactory(resource=self.fixture.resource)
        url = factories.RobotAccountFactory.get_url(account)

        response = self.client.patch(url, {"username": "foo"})
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

        account.refresh_from_db()
        self.assertEqual(account.username, "foo")

    @data("admin", "manager")
    def test_unauthorized_user_can_not_update_robot_account(self, user):
        self.client.force_authenticate(getattr(self.fixture, user))
        account = factories.RobotAccountFactory(resource=self.fixture.resource)
        url = factories.RobotAccountFactory.get_url(account)

        response = self.client.patch(url, {"username": "foo"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, response.data)

    def test_robot_account_response_contains_key_fingerprints(self):
        self.client.force_authenticate(self.fixture.service_owner)
        ssh_keys = [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRmKSYeNxfyNGIoYqQCXUjLlMFJSCX/Jx+k0ODlg0xpMMlBEEK test"
        ]
        account = factories.RobotAccountFactory(
            resource=self.fixture.resource, keys=ssh_keys
        )
        url = factories.RobotAccountFactory.get_url(account)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(1, len(response.data["keys"]))
        fingerprint_md5, fingerprint_sha256, fingerprint_sha512 = (
            get_ssh_key_fingerprints(ssh_keys[0])
        )

        self.assertEqual(fingerprint_md5, response.data["fingerprints"][0]["md5"])
        self.assertEqual(fingerprint_sha256, response.data["fingerprints"][0]["sha256"])
        self.assertEqual(fingerprint_sha512, response.data["fingerprints"][0]["sha512"])
