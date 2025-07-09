from waldur_core.core import WaldurExtension


class MarketplaceOpenPortalExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_mastermind.marketplace_openportal"

    @staticmethod
    def is_assembly():
        return True

    @staticmethod
    def celery_tasks():
        from datetime import timedelta

        return {
            "send-messages-about-pending-openportal-orders": {
                "task": "waldur_mastermind.marketplace_openportal.send_messages_about_pending_orders",
                "schedule": timedelta(hours=1),
                "args": (),
            },
        }
