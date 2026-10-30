from django.urls import re_path

from . import views


def register_in(router):
    router.register(r"form-flows", views.FormFlowViewSet, basename="form-flow")
    router.register(
        r"proposal-form-calls", views.CallFormFlowViewSet, basename="proposal-form-call"
    )
    router.register(
        r"proposal-forms", views.ProposalFormViewSet, basename="proposal-form"
    )


urlpatterns = [
    re_path(
        r"^api/formbricks-connection/$",
        views.FormbricksConnectionView.as_view(),
        name="formbricks-connection",
    ),
    re_path(
        r"^api/formbricks-connection/test/$",
        views.FormbricksConnectionTestView.as_view(),
        name="formbricks-connection-test",
    ),
    re_path(
        r"^api/formbricks-surveys/$",
        views.FormbricksSurveyListView.as_view(),
        name="formbricks-surveys",
    ),
    re_path(
        r"^api/proposal-form-return/$",
        views.ProposalFormReturnView.as_view(),
        name="proposal-form-return",
    ),
    re_path(
        r"^api/proposal-form-redirect/$",
        views.ProposalFormRedirectView.as_view(),
        name="proposal-form-redirect",
    ),
    re_path(
        r"^api/proposal-form-webhook/$",
        views.ProposalFormWebhookView.as_view(),
        name="proposal-form-webhook",
    ),
]
