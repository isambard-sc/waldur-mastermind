import logging

from waldur_mastermind.marketplace import registrators as marketplace_registrators

from . import PLUGIN_NAME

logger = logging.getLogger(__name__)


class OpenPortalRegistrator(marketplace_registrators.MarketplaceRegistrator):
    plugin_name = PLUGIN_NAME

    @classmethod
    def convert_quantity(cls, usage, component_type):
        # OpenPortal reports usage in node hours - no conversion needed
        logger.info(f"Converting OpenPortal node-hour usage {usage} for component type {component_type} into node hours {usage}")
        return usage
