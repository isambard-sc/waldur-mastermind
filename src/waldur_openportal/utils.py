import itertools
import re

from django.utils import timezone

from waldur_core.core import utils as core_utils
from waldur_core.structure.managers import (
    get_connected_customers,
    get_connected_projects,
)
from waldur_openportal import models

MAPPING = {
    "node_usage": "op_node_usage",
}

FIELD_NAMES = MAPPING.keys()

QUOTA_NAMES = MAPPING.values()


def format_current_month():
    today = timezone.now()
    month_start = core_utils.month_start(today).strftime("%Y-%m-%d")
    month_end = core_utils.month_end(today).strftime("%Y-%m-%d")
    return month_start, month_end


def sanitize_allocation_name(name):
    incorrect_symbols_regex = r"[^%s]+" % models.OPENPORTAL_ALLOCATION_REGEX
    return re.sub(incorrect_symbols_regex, "", name)


def get_customer_allocations(user):
    """
    Return the allocations to the user associated with being a customer.
    This will typically be all of the allocations associated with customer
    roles in, e.g. an organisation
    """
    connected_customers = get_connected_customers(user)

    customer_allocations = models.Allocation.objects.filter(
        is_active=True, project__customer__in=connected_customers
    )

    print(f"customer_allocations for user {user}: {customer_allocations}")

    return customer_allocations


def get_project_allocations(user):
    """
    Return all of the allocations associated with the passed user
    to any project. This gives the projects in which the user is active.
    Projects in which the user is inactive are ignored
    """
    connected_projects = get_connected_projects(user)

    project_allocations = models.Allocation.objects.filter(
        is_active=True, project__in=connected_projects
    )

    print(f"project_allocations for user {user}: {project_allocations}")
    return project_allocations
