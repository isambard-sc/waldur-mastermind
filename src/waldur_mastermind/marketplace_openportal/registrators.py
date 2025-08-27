from waldur_mastermind.marketplace import registrators as marketplace_registrators
from decimal import Decimal

from . import PLUGIN_NAME


class OpenPortalRegistrator(marketplace_registrators.MarketplaceRegistrator):
    plugin_name = PLUGIN_NAME

    @classmethod
    def convert_quantity(cls, usage: int | float | Decimal, component_type: str) -> int:
        return usage
