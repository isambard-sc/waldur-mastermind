from . import views


def register_in(router):
    router.register(
        r"marketplace-openportal",
        views.OpenPortalViewSet,
        basename="marketplace-openportal",
    )
