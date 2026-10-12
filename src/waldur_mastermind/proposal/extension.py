from datetime import timedelta

from waldur_core.core import WaldurExtension


class ProposalExtension(WaldurExtension):
    class Settings:
        # See formbricks_flows.py / formbricks_client.py for how these are
        # used. TODO(formbricks-setup): every value here is a placeholder -
        # see the "Formbricks setup checklist" produced at the end of this
        # feature's implementation.
        WALDUR_PROPOSAL = {
            # Public base URL of the Formbricks instance, used to build the
            # survey links a Lead's *browser* is sent to
            # (build_survey_url/build_prefilled_url). No trailing slash.
            "FORMBRICKS_BASE_URL": "https://formbricks.localhost",
            # Formbricks base URL reachable *from inside the waldur-mastermind
            # containers* - used only by get_response()/get_survey(), which run
            # server-side. Deliberately separate from FORMBRICKS_BASE_URL:
            # "formbricks.localhost" resolves to loopback inside every
            # container (same class of problem the webhook URL had in the
            # other direction), so this needs the actual docker-network
            # address instead. Verified reachable as of 2026-08-26 - tied to
            # this docker-compose project's container naming, so it'll need
            # updating if that changes (e.g. a different COMPOSE_PROJECT_NAME).
            "FORMBRICKS_MANAGEMENT_API_URL": "http://waldur-docker-compose-formbricks-1:3000",
            # Shared secret configured on the Formbricks webhook itself;
            # verifies inbound webhook signatures (formbricks_client.verify_signature).
            "FORMBRICKS_WEBHOOK_SECRET": "",
            # Formbricks Management API key; authenticates Waldur's outbound
            # get_response()/get_survey() calls.
            "FORMBRICKS_API_KEY": "",
            # Waldur frontend URL a Lead lands on after finishing a Formbricks
            # flow. {proposal_uuid} is substituted by views._get_formbricks_flow_complete_url.
            "FRONTEND_FLOW_COMPLETE_URL_TEMPLATE": "https://localhost/proposals/{proposal_uuid}/",
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
            "notify-proposal-creator-on-submission-deadline-approaching": {
                "task": "waldur_mastermind.proposal.notify_proposal_creator_on_submission_deadline_approaching",
                "schedule": timedelta(hours=24),
                "args": (),
            },
            "notify-reviewer-on-review-deadline-approaching": {
                "task": "waldur_mastermind.proposal.notify_reviewer_on_review_deadline_approaching",
                "schedule": timedelta(hours=24),
                "args": (),
            },
            "mark-expired-assignment-batches": {
                "task": "waldur_mastermind.proposal.mark_expired_assignment_batches",
                "schedule": timedelta(minutes=15),
                "args": (),
            },
            "start-evaluation-for-closed-rounds": {
                "task": "waldur_mastermind.proposal.start_evaluation_for_closed_rounds",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "mark-expired-reviewer-pool-invitations": {
                "task": "waldur_mastermind.proposal.mark_expired_reviewer_pool_invitations",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "mark-expired-workflow-steps": {
                "task": "waldur_mastermind.proposal.mark_expired_workflow_steps",
                "schedule": timedelta(hours=1),
                "args": (),
            },
            "send-workflow-step-deadline-reminders": {
                "task": "waldur_mastermind.proposal.send_workflow_step_deadline_reminders",
                "schedule": timedelta(hours=24),
                "args": (),
            },
            "send-assignment-expiry-reminders": {
                "task": "waldur_mastermind.proposal.send_assignment_expiry_reminders",
                "schedule": timedelta(hours=24),
                "args": (),
            },
            "notify-managers-of-expired-batches": {
                "task": "waldur_mastermind.proposal.notify_managers_of_expired_batches",
                "schedule": timedelta(minutes=30),
                "args": (),
            },
        }
