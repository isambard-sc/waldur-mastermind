from waldur_core.core import WaldurExtension


class AIReportingExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_mastermind.ai_reporting"

    @staticmethod
    def rest_urls():
        from .urls import register_in

        return register_in

    @staticmethod
    def celery_tasks():
        from celery.schedules import crontab

        return {
            "waldur-ai-reporting-cleanup-old-messages": {
                "task": "waldur_mastermind.ai_reporting.cleanup_old_reporting_messages",
                "schedule": crontab(minute=0, hour=3),  # 3 AM daily
                "args": (),
            },
            "waldur-ai-reporting-cleanup-old-files": {
                "task": "waldur_mastermind.ai_reporting.cleanup_old_reporting_files",
                "schedule": crontab(minute=30, hour=3),  # 3:30 AM daily
                "args": (),
            },
        }
