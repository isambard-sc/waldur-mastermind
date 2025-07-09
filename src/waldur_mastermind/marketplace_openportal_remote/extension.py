from waldur_core.core import WaldurExtension


class MarketplaceOpenPortalRemoteExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_mastermind.marketplace_openportal_remote"

    @staticmethod
    def is_assembly():
        return True

    @staticmethod
    def celery_tasks():
        from datetime import timedelta

        return {
            "send-messages-about-pending-openportal-remote-orders": {
                "task": "waldur_mastermind.marketplace_openportal_remote.send_messages_about_pending_orders",
                "schedule": timedelta(hours=1),
                "args": (),
            },
        }
