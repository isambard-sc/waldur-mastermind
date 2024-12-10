from waldur_core.core import WaldurExtension


class OpenPortalExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_openportal"

    @staticmethod
    def rest_urls():
        from .urls import register_in

        return register_in

    @staticmethod
    def get_cleanup_executor():
        from waldur_openportal.executors import OpenPortalCleanupExecutor

        return OpenPortalCleanupExecutor
