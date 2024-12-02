import logging

from celery import shared_task

from waldur_openportal.models import Job
from waldur_openportal import OpenPortalException
from waldur_core.core.utils import deserialize_instance

from . import utils


logger = logging.getLogger(__name__)


@shared_task(name="waldur_openportal.sync")
def sync():
    utils.sync()
