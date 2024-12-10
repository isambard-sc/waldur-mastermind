import math

from waldur_mastermind.marketplace import registrators as marketplace_registrators

from . import PLUGIN_NAME


class OpenPortalRegistrator(marketplace_registrators.MarketplaceRegistrator):
    plugin_name = PLUGIN_NAME

    @classmethod
    def convert_quantity(cls, usage, component_type):
        seconds_in_hour = 3600
        return math.ceil(1.0 * usage / seconds_in_hour)
