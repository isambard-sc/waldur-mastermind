import logging
import time
import datetime

from waldur_core.openportal import OpenPortalException
from waldur_core.openportal.client import OpenPortalClient

from .models import Job

logger = logging.getLogger(__name__)

def sync():
    try:
        client = OpenPortalClient()
    except OpenPortalException as e:
        logger.error("Failed to connect to OpenPortal: %s", e)
        return

    # find all of the jobs that are in pending state
    jobs = Job.objects.filter(state=Job.States.PENDING)

    for job in jobs:
        try:
            op_job = client.get(job.backend_id)
        except OpenPortalException as e:
            logger.error("Failed to get job %s: %s", job.backend_id, e)
            job.state = Job.States.ERRED
            job.error_message = str(e)
            job.save()
            continue

        op_job.update()

        if op_job.is_error:
            logger.error("Job %s has failed: %s", job.backend_id, op_job.error_message)
            job.state = Job.States.ERRED
            job.error_message = op_job.error_message
            job.save()
        elif op_job.is_finished:
            logger.info("Job %s has finished: %s", job.backend_id, job.result)
            job.state = Job.States.OK
            job.report = op_job.result
            job.save()


def submit_job(job):
    try:
        client = OpenPortalClient()
    except OpenPortalException as e:
        logger.error("Failed to connect to OpenPortal: %s", e)
        raise e

    try:
        op_job = client.run(job.command)
    except OpenPortalException as e:
        logger.error("Failed to run command %s: %s", job.command, e)
        raise e

    job.backend_id = op_job.uid

    # give it 2 seconds to complete before passing to
    # a long running celery task to monitor
    now = datetime.datetime.now()
    op_job.update()

    while not op_job.is_finished and datetime.datetime.now() - now < datetime.timedelta(seconds=2):
        time.sleep(0.1)
        op_job.update()

    if op_job.is_error:
        job.state = Job.States.ERRED
        job.error_message = op_job.error_message
        job.save()

    elif op_job.is_finished:
        job.state = Job.States.OK
        job.report = op_job.result
        job.save()

    job.save()
