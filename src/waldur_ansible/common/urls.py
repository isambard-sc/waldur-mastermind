from . import views


def register_in(router):
    router.register(
        r'applications', views.ApplicationsSummaryViewSet, basename='applications'
    )
