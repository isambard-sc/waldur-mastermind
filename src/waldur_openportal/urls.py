from django.urls import path

from . import views
from .api import access_for_email

def register_in(router):
    router.register(
        r"openportal-allocations", views.AllocationViewSet, basename="openportal-allocation"
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
        r"openportal-userinfo",
        views.UserInfoViewSet,
        basename="openportal-userinfo",
    )
    router.register(
        r"openportal-projectinfo",
        views.ProjectInfoViewSet,
        basename="openportal-projectinfo",
    )

urlpatterns = [
    path("openportal/access_for_email", access_for_email),
]
