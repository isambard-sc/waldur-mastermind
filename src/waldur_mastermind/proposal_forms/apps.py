from django.apps import AppConfig


class ProposalFormsConfig(AppConfig):
    name = "waldur_mastermind.proposal_forms"
    verbose_name = "Proposal application forms"

    def ready(self):
        from . import handlers  # noqa: F401 - connects the serializer field hooks
