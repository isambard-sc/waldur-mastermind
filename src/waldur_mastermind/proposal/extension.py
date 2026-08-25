from datetime import timedelta

from waldur_core.core import WaldurExtension


class ProposalExtension(WaldurExtension):
    class Settings:
        # See formbricks_flows.py / formbricks_client.py for how these are
        # used. TODO(formbricks-setup): every value here is a placeholder -
        # see the "Formbricks setup checklist" produced at the end of this
        # feature's implementation.
        WALDUR_PROPOSAL = {
            # Public base URL of the Formbricks instance, e.g.
            # "https://forms.example.org". No trailing slash.
            "FORMBRICKS_BASE_URL": "https://formbricks.localhost",
            # Shared secret configured on the Formbricks webhook itself;
            # verifies inbound webhook signatures (formbricks_client.verify_signature).
            "FORMBRICKS_WEBHOOK_SECRET": "",
            # Formbricks Management API key; authenticates Waldur's outbound
            # get_response()/get_survey() calls.
            "FORMBRICKS_API_KEY": "",
            # Waldur frontend URL a Lead lands on after finishing a Formbricks
            # flow. {proposal_uuid} is substituted by views._get_formbricks_flow_complete_url.
            "FRONTEND_FLOW_COMPLETE_URL_TEMPLATE": "https://localhost/proposals/{proposal_uuid}",
        }

    @staticmethod
    def django_app():
        return "waldur_mastermind.proposal"

    @staticmethod
    def is_assembly():
        return True

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
        return {
            "create-reviews-if-strategy-is-after-round": {
                "task": "waldur_mastermind.proposal.create_reviews_if_strategy_is_after_round",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "create-reviews-if-strategy-is-after-proposal": {
                "task": "waldur_mastermind.proposal.create_reviews_if_strategy_is_after_proposal",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "proposals-for-ended-rounds-should-be-cancelled": {
                "task": "waldur_mastermind.proposal.proposals_for_ended_rounds_should_be_cancelled",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "expired-reviews-should-be-cancelled": {
                "task": "waldur_mastermind.proposal.expired_reviews_should_be_cancelled",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "notify_reviewer_on_round_start": {
                "task": "waldur_mastermind.proposal.notify_reviewer_on_round_start",
                "schedule": timedelta(hours=24),
                "args": (),
            },
            "notify_manager_on_round_cutoff": {
                "task": "waldur_mastermind.proposal.notify_manager_on_round_cutoff",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "send-stale-proposal-reminders": {
                "task": "waldur_mastermind.proposal.send_stale_proposal_reminders",
                "schedule": timedelta(days=1),
                "args": (),
            },
            "delete-stale-proposals": {
                "task": "waldur_mastermind.proposal.delete_stale_proposals",
                "schedule": timedelta(days=1),
                "args": (),
            },
        }
