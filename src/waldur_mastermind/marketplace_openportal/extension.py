from waldur_core.core import WaldurExtension


class MarketplaceOpenPortalExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_mastermind.marketplace_openportal"

    @staticmethod
    def rest_urls():
        from .urls import register_in

        return register_in

    @staticmethod
    def is_assembly():
        return True

    @staticmethod
    def celery_tasks():
        from datetime import timedelta

        return {
            "waldur-create-offering-users-for-remote-openportal-offerings": {
                "task": "waldur_mastermind.marketplace_openportal.sync_offering_users",
                "schedule": timedelta(days=1),
                "args": (),
            },
            "mark-offering-backend-as-disconnected-after-timeout": {
                "task": "waldur_mastermind.marketplace_openportal.mark_offering_backend_as_disconnected_after_timeout",
                "schedule": timedelta(hours=1),
                "args": (),
            },
        }
