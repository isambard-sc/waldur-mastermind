import logging

from celery import shared_task

from . import utils


logger = logging.getLogger(__name__)


@shared_task(name="waldur_openportal.sync")
def sync():
    utils.sync()
