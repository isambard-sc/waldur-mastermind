from . import views


def register_in(router):
    router.register(r"openportal-jobs", views.JobViewSet, basename="openportal-job")
