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
            # This task re-tries to add or remove users in case
            # user management failed when called directly
            "waldur-openportal-sync-users": {
                "task": "waldur_openportal.sync",
                "schedule": timedelta(minutes=59),
                "args": (),
            },
            # This task synchronises all usage from the OpenPortal resources
            # back to the portal - this is the "near-real time" consumption
            # data
            "waldur-openportal-sync-usage": {
                "task": "waldur_openportal.sync_usage",
                "schedule": timedelta(minutes=7),
                "args": (),
            },
            # This task checks if we need to email project members with
            # their fortnightly project consumption statistics email
            "waldur-openportal-send-notifications": {
                "task": "waldur_openportal.send_notifications",
                "schedule": timedelta(minutes=47),
                "args": (),
            },
            # This task re-tries to add or update remote projects
            # in case project management failed when called directly.
            # This is important for, e.g. when a project needs approving,
            # and it can be a while until approval is granted
            "waldur-openportal-sync-remote": {
                "task": "waldur_openportal.sync_remote",
                "schedule": timedelta(minutes=29),
                "args": (),
            },
            # This task synchronises all usage from remote OpenPortal resources
            # back to this remote portal. This is the "near-real time"
            # consumption data visible in the remote portal
            "waldur-openportal-sync-remote-usage": {
                "task": "waldur_openportal.sync_remote_usage",
                "schedule": timedelta(minutes=9),
                "args": (),
            },
        }

    @staticmethod
    def get_cleanup_executor():
        from waldur_openportal.executors import OpenPortalCleanupExecutor

        return OpenPortalCleanupExecutor
