import logging

from waldur_core.core import WaldurExtension

logger = logging.getLogger(__name__)


class OpenPortalExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_openportal"

    @staticmethod
    def django_urls():
        from .urls import urlpatterns

        logger.info("OpenPortalExtension urlpatterns: %s", urlpatterns)

        return urlpatterns

    @staticmethod
    def rest_urls():
        from .urls import register_in

        return register_in

    @staticmethod
    def celery_tasks():
        from datetime import timedelta

        return {
            "waldur-openportal-sync": {
                "task": "waldur_openportal.sync",
                "schedule": timedelta(hours=2),
                "args": (),
            },
        }

    @staticmethod
    def get_cleanup_executor():
        from waldur_openportal.executors import OpenPortalCleanupExecutor

        return OpenPortalCleanupExecutor
