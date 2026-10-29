from waldur_core.core import WaldurExtension


class ProposalFormsExtension(WaldurExtension):
    """Proposal applications filled in through Formbricks surveys.

    Fork-only. Everything Formbricks needs lives here - its connection
    settings, its survey chains (flows), which call uses which flow, and the
    applicants' answers - so upstream's proposal app is untouched apart from
    the serializer fields this app adds to it through pre_serializer_fields.
    Off until the connection is configured and enabled through the API.
    """

    class Settings:
        pass

    @staticmethod
    def django_app():
        return "waldur_mastermind.proposal_forms"

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
