from django.test import TestCase

from . import factories, fixtures, utils


@utils.override_plugin_settings(ENABLED=True)
class QuotasTest(TestCase):
    def setUp(self):
        self.fixture = fixtures.OpenPortalFixture()

        allocation1 = factories.AllocationFactory(
            service_settings=self.fixture.settings, project=self.fixture.project
        )
        allocation1.node_usage = 1000
        allocation1.save()

        allocation2 = factories.AllocationFactory(
            service_settings=self.fixture.settings, project=self.fixture.project
        )
        allocation2.node_usage = 5000
        allocation2.save()

        self.expected_node_usage = allocation1.node_usage + allocation2.node_usage

    def test_project_quotas_are_updated(self):
        actual_node_usage = self.fixture.project.get_quota_usage("op_node_usage")
        self.assertEqual(self.expected_node_usage, actual_node_usage)

    def test_customer_quotas_are_updated(self):
        actual_node_usage = self.fixture.customer.get_quota_usage("op_node_usage")
        self.assertEqual(self.expected_node_usage, actual_node_usage)

    def test_allocation_count_is_updated_for_project(self):
        self.assertEqual(self.fixture.project.get_quota_usage("op_allocation_count"), 2)
        self.assertEqual(
            fixtures.OpenPortalFixture().project.get_quota_usage("op_allocation_count"),
            0,
        )
