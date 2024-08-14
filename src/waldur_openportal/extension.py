from waldur_core.core import WaldurExtension


class OpenPortalExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_openportal"

    @staticmethod
    def is_assembly():
        return True

    @staticmethod
    def rest_urls():
        from .urls import register_in

        return register_in

    @staticmethod
    def celery_tasks():
        from datetime import timedelta

        return {
            "waldur-openportal-pull-jobs": {
                "task": "waldur_openportal.pull_jobs",
                "schedule": timedelta(hours=1),
                "args": (),
            },
        }
