import math
import logging

from waldur_mastermind.marketplace import registrators as marketplace_registrators

from . import PLUGIN_NAME

logger = logging.getLogger(__name__)


class OpenPortalRegistrator(marketplace_registrators.MarketplaceRegistrator):
    plugin_name = PLUGIN_NAME

    @classmethod
    def convert_quantity(cls, usage, component_type):
        # OpenPortal reports usage in node seconds. We need to convert
        # this into node hours
        logger.info(f"Converting OpenPortal node-second usage {usage} for component type {component_type} into node hours {usage/3600.0}")
        seconds_in_hour = 3600
        return math.ceil(1.0 * usage / seconds_in_hour)
