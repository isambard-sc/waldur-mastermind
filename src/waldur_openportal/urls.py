from django.urls import re_path

from . import views
from .api import (
    access_for_email,
    project_spend_info,
    customer_spend_info,
    fetch_job,
    whoami,
    get_api_token,
)


def register_in(router):
    router.register(
        r"openportal-allocations",
        views.AllocationViewSet,
        basename="openportal-allocation",
    )
    router.register(
        r"openportal-remote-allocations",
        views.RemoteAllocationViewSet,
        basename="openportal-remote-allocation",
    )
    router.register(
        r"openportal-allocation-user-usage",
        views.AllocationUserUsageViewSet,
        basename="openportal-allocation-user-usage",
    )
    router.register(
        r"openportal-associations",
        views.AssociationViewSet,
        basename="openportal-association",
    )
    router.register(
        r"openportal-remote-associations",
        views.RemoteAssociationViewSet,
        basename="openportal-remote-association",
    )
    router.register(
        r"openportal-userinfo",
        views.UserInfoViewSet,
        basename="openportal-userinfo",
    )
    router.register(
        r"openportal-projectinfo",
        views.ProjectInfoViewSet,
        basename="openportal-projectinfo",
    )
    router.register(
        r"openportal-project-template",
        views.ProjectTemplateViewSet,
        basename="openportal-project-template",
    )
    router.register(
        r"openportal-managed-projects",
        views.ManagedProjectViewSet,
        basename="openportal-managed-project",
    )
    router.register(
        r"openportal-unmanaged-projects",
        views.UnmanagedProjectViewSet,
        basename="openportal-unmanaged-project",
    )


urlpatterns = [
    re_path(
        r"^api/openportal/access_for_email/",
        access_for_email,
        name="access-for-email",
    ),
    re_path(
        r"^api/openportal/project_spend_info/",
        project_spend_info,
        name="project-spend-info",
    ),
    re_path(
        r"^api/openportal/customer_spend_info/",
        customer_spend_info,
        name="customer-spend-info",
    ),
    re_path(
        r"^api/openportal/fetch_job/",
        fetch_job,
        name="fetch-job",
    ),
    re_path(
        r"^api/openportal/whoami/",
        whoami,
        name="whoami",
    ),
    re_path(
        r"^api/openportal/get_api_token/",
        get_api_token,
        name="get_api_token",
    ),
]
