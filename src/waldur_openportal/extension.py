from waldur_core.core import WaldurExtension


class OpenPortalExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_openportal"

    @staticmethod
    def django_urls():
        from .urls import urlpatterns
        return urlpatterns

    @staticmethod
    def rest_urls():
        from .urls import register_in

        return register_in

    @staticmethod
    def celery_tasks():
        from datetime import timedelta

        return {
            "waldur-openportal-sync-users": {
                "task": "waldur_openportal.sync",
                "schedule": timedelta(minutes=60),
                "args": (),
            },
            "waldur-openportal-sync-usage": {
                "task": "waldur_openportal.sync_usage",
                "schedule": timedelta(minutes=29),
                "args": (),
            },
        }

    @staticmethod
    def get_cleanup_executor():
        from waldur_openportal.executors import OpenPortalCleanupExecutor

        return OpenPortalCleanupExecutor
