from django.apps import AppConfig


class AIReportingConfig(AppConfig):
    name = "waldur_mastermind.ai_reporting"
    verbose_name = "AI Reporting"

    def ready(self):
        from django.db.models import signals

        from . import handlers
        from .models import ReportingFile, ReportingSession

        signals.post_delete.connect(
            handlers.on_reporting_file_deleted,
            sender=ReportingFile,
            dispatch_uid="waldur_mastermind.ai_reporting.on_reporting_file_deleted",
        )
        signals.post_delete.connect(
            handlers.on_reporting_session_deleted,
            sender=ReportingSession,
            dispatch_uid="waldur_mastermind.ai_reporting.on_reporting_session_deleted",
        )
