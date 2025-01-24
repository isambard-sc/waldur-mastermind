import logging
from waldur_mastermind.marketplace import registrators as marketplace_registrators
from decimal import Decimal

from . import PLUGIN_NAME

logger = logging.getLogger(__name__)


class OpenPortalRegistrator(marketplace_registrators.MarketplaceRegistrator):
    plugin_name = PLUGIN_NAME

    @classmethod
    def convert_quantity(cls, usage: int | float | Decimal, component_type: str) -> int:
        logger.info(f"OpenPortal Converting quantity for usage: {usage} and component_type: {component_type}")
        # openportal already converted to node hours
        return usage
