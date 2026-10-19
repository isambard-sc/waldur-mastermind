from waldur_core.core import WaldurExtension


class AIReportingExtension(WaldurExtension):
    @staticmethod
    def django_app():
        return "waldur_mastermind.ai_reporting"

    @staticmethod
    def rest_urls():
        from .urls import register_in

        return register_in
