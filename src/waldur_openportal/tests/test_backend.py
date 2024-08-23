from unittest import mock

from django.conf import settings as django_settings
from django.test import TestCase
from freezegun import freeze_time

from waldur_freeipa import models as freeipa_models
from waldur_openportal import models
from waldur_openportal.client import OpenPortalClient
from waldur_openportal.parser import OpenPortalReportLine

from . import factories, fixtures

VALID_REPORT = """
allocation1|cpu=1,mem=51200M,node=1,gres/gpu=1,gres/gpu:tesla=1|00:01:00|user1|
allocation1|cpu=2,mem=51200M,node=2,gres/gpu=2,gres/gpu:tesla=1|00:02:00|user2|
"""

INVALID_ASSOCIATIONS = """
allocation1|
allocation1|
"""

VALID_ASSOCIATIONS = """
allocation1|
allocation1|cpu=400,mem=100M,gres/gpu=120
allocation1|
"""

VALID_USERS_ASSOCIATIONS = """
allocation1|
allocation1|user1
allocation1|user2
allocation1|user3
"""


class BackendTest(TestCase):
    def setUp(self):
        self.fixture = fixtures.OpenPortalFixture()
        self.allocation = self.fixture.allocation
        self.account = self.allocation.backend_id

    def prepare_limits_check(self, quotas):
        self.allocation.cpu_limit = quotas["CPU"]
        self.allocation.gpu_limit = quotas["GPU"]
        self.allocation.ram_limit = quotas["RAM"]
        self.allocation.save()

        template = (
            "sacctmgr --parsable2 --noheader --immediate"
            " modify account %s set GrpTRESMins=cpu=%d,gres/gpu=%d,mem=%d"
        )

        context = (
            self.account,
            self.allocation.cpu_limit,
            self.allocation.gpu_limit,
            self.allocation.ram_limit,
        )

        return [
            "ssh",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            "root@localhost",
            "-p",
            "22",
            "-i",
            "/etc/waldur/id_rsa",
            template % context,
        ]

    @mock.patch("subprocess.check_output")
    def test_allocation_creation(self, check_output):
        backend = self.allocation.get_backend()
        backend.create_allocation(self.allocation)

        self.allocation.refresh_from_db()
        default_limits = django_settings.WALDUR_OPENPORTAL["DEFAULT_LIMITS"]
        self.assertEqual(self.allocation.cpu_limit, default_limits["CPU"])
        self.assertEqual(self.allocation.gpu_limit, default_limits["GPU"])
        self.assertEqual(self.allocation.ram_limit, default_limits["RAM"])

    @mock.patch("subprocess.check_output")
    def test_usage_synchronization(self, check_output):
        check_output.return_value = VALID_REPORT.replace("allocation1", self.account)

        backend = self.allocation.get_backend()
        backend.sync_usage()
        self.allocation.refresh_from_db()

        self.assertEqual(self.allocation.cpu_usage, 1 + 2 * 2)
        self.assertEqual(self.allocation.gpu_usage, 1 + 2 * 2)
        self.assertEqual(self.allocation.ram_usage, (1 + 2) * 51200)

    @freeze_time("2017-10-16")
    @mock.patch("subprocess.check_output")
    def test_usage_per_user(self, check_output):
        check_output.return_value = VALID_REPORT.replace("allocation1", self.account)

        user1 = self.fixture.manager
        user2 = self.fixture.admin

        freeipa_models.Profile.objects.create(user=user1, username="user1")
        freeipa_models.Profile.objects.create(user=user2, username="user2")

        backend = self.allocation.get_backend()
        backend.sync_usage()

        user1_allocation_usage = models.AllocationUserUsage.objects.get(
            allocation=self.allocation, year=2017, month=10, user=user1
        )

        self.assertEqual(user1_allocation_usage.cpu_usage, 1)
        self.assertEqual(user1_allocation_usage.gpu_usage, 1)
        self.assertEqual(user1_allocation_usage.ram_usage, 51200)

        user2_allocation_usage = models.AllocationUserUsage.objects.get(
            allocation=self.allocation, year=2017, month=10, user=user2
        )
        self.assertEqual(user2_allocation_usage.cpu_usage, 2 * 2)
        self.assertEqual(user2_allocation_usage.gpu_usage, 2 * 2)
        self.assertEqual(user2_allocation_usage.ram_usage, 2 * 51200)

    @mock.patch("subprocess.check_output")
    def test_set_default_resource_limits(self, check_output):
        default_limits = django_settings.WALDUR_OPENPORTAL["DEFAULT_LIMITS"]
        command = self.prepare_limits_check(default_limits)

        backend = self.allocation.get_backend()
        backend.set_resource_limits(self.allocation)

        check_output.assert_called_once_with(command, encoding="utf-8", stderr=-2)

    @mock.patch("subprocess.check_output")
    def test_set_custom_resource_limits(self, check_output):
        quotas_dict = {
            "CPU": 1000,
            "GPU": 2000,
            "RAM": 3000,
        }
        command = self.prepare_limits_check(quotas_dict)

        backend = self.allocation.get_backend()
        backend.set_resource_limits(self.allocation)

        check_output.assert_called_once_with(command, encoding="utf-8", stderr=-2)

    @mock.patch("subprocess.check_output")
    def test_pull_allocation(self, check_output):
        association_line = VALID_ASSOCIATIONS.replace("allocation1", self.account)
        check_output.return_value = association_line

        with mock.patch.object(OpenPortalClient, "get_usage_report") as usage_report:
            report = VALID_REPORT.replace("allocation1", self.account)
            usage_report.return_value = [
                OpenPortalReportLine(line)
                for line in report.splitlines()
                if "|" in line
            ]

            backend = self.allocation.get_backend()
            backend.pull_allocation(self.allocation)
            self.allocation.refresh_from_db()

            self.assertEqual(self.allocation.cpu_limit, 400)
            self.assertEqual(self.allocation.gpu_limit, 120)
            self.assertEqual(self.allocation.ram_limit, 100)

    def test_name_changing(self):
        sample_name = "al*lo$ca#tio#n_12~!34-5"
        correct_name = "allocation_1234-5"
        prefix = django_settings.WALDUR_OPENPORTAL["ALLOCATION_PREFIX"]

        allocation = factories.AllocationFactory(name=sample_name)
        hexpart = allocation.uuid.hex[:5]

        final_correct_name = (f"{prefix}{hexpart}_{correct_name}")[
            : models.OPENPORTAL_ALLOCATION_NAME_MAX_LEN
        ]
        backend = allocation.get_backend()
        result_name = backend.get_allocation_name(allocation)

        self.assertEqual(result_name, final_correct_name)

    @mock.patch("subprocess.check_output")
    def test_allocation_zero_usage_created(self, check_output):
        association = f"{self.account}|cpu=400,mem=100M,gres/gpu=120"
        check_output.return_value = association

        with mock.patch.object(OpenPortalClient, "get_usage_report") as usage_report:
            usage_report.return_value = []

            backend = self.allocation.get_backend()
            backend.pull_allocation(self.allocation)
            self.allocation.refresh_from_db()

            self.assertEqual(self.allocation.cpu_usage, 0)
            self.assertEqual(self.allocation.gpu_usage, 0)
            self.assertEqual(self.allocation.ram_usage, 0)

    @mock.patch("subprocess.check_output")
    def test_allocation_limits_are_not_changed_after_if_association_lines_are_invalid(
        self, check_output
    ):
        invalid_association = INVALID_ASSOCIATIONS.replace("allocation1", self.account)
        check_output.return_value = invalid_association
        cpu_limit_old = self.allocation.cpu_limit
        gpu_limit_old = self.allocation.gpu_limit
        ram_limit_old = self.allocation.ram_limit

        with mock.patch.object(OpenPortalClient, "get_usage_report") as usage_report:
            report = VALID_REPORT.replace("allocation1", self.account)
            usage_report.return_value = [
                OpenPortalReportLine(line)
                for line in report.splitlines()
                if "|" in line
            ]

            backend = self.allocation.get_backend()
            backend.pull_allocation(self.allocation)
            self.allocation.refresh_from_db()

            self.assertEqual(self.allocation.cpu_limit, cpu_limit_old)
            self.assertEqual(self.allocation.gpu_limit, gpu_limit_old)
            self.assertEqual(self.allocation.ram_limit, ram_limit_old)

    @mock.patch("subprocess.check_output")
    def test_allocation_associations(self, check_output):
        check_output.return_value = VALID_USERS_ASSOCIATIONS.replace(
            "allocation1", self.account
        )

        stale_association = factories.AssociationFactory(
            allocation=self.allocation, username="user4"
        )

        backend = self.allocation.get_backend()
        backend._update_allocation_associations(self.allocation)

        self.allocation.refresh_from_db()
        self.assertEqual(3, self.allocation.associations.count())
        self.assertNotIn(stale_association, self.allocation.associations.all())
