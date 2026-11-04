from waldur_mastermind.ai_reporting import views


def register_in(router):
    router.register(
        r"ai-reporting-messages",
        views.ReportingMessageViewSet,
        basename="ai-reporting-message",
    )
    router.register(
        r"ai-reporting-files",
        views.ReportingFileViewSet,
        basename="ai-reporting-file",
    )
