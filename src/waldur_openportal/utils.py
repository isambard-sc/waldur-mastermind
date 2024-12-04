import itertools
import logging
import time
import re
import datetime

from waldur_core.structure.managers import (
    get_connected_customers,
    get_connected_projects,
)

from .client import OpenPortalClient, OpenPortalException

from .models import Job
from . import models

logger = logging.getLogger(__name__)

MAPPING = {
    "cpu_usage": "nc_cpu_usage",
    "gpu_usage": "nc_gpu_usage",
    "ram_usage": "nc_ram_usage",
}

FIELD_NAMES = MAPPING.keys()

QUOTA_NAMES = MAPPING.values()


def sync():
    try:
        client = OpenPortalClient()
    except OpenPortalException as e:
        logger.error("Failed to connect to OpenPortal: %s", e)
        return

    client.health(logger)

    # find all of the jobs that are in pending state
    jobs = Job.objects.filter(state__in=[Job.States.CREATION_SCHEDULED,
                                         Job.States.CREATING,
                                         Job.States.UPDATE_SCHEDULED,
                                         Job.States.UPDATING])

    logger.info("Found %d jobs in unfinished state", len(jobs))

    for job in jobs:
        try:
            op_job = client.get(job.backend_id)
        except OpenPortalException as e:
            logger.error("Failed to get job %s: %s", job.backend_id, e)
            job.state = Job.States.ERRED
            job.report = str(e)
            job.save()
            continue

        op_job.update()

        if op_job.is_error:
            logger.error("Job %s has failed: %s", job.backend_id, op_job.error_message)
            job.state = Job.States.ERRED
            job.report = op_job.error_message
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

    # make sure that the job is in the "CREATION_SCHEDULED" state
    if job.state != Job.States.CREATION_SCHEDULED:
        logger.error(f"Job {job} is not in the 'CREATION_SCHEDULED' state - state: {job.state}")
        raise OpenPortalException("Job is not in the 'CREATION_SCHEDULED' state")

    # make sure that the user submitting the job is a staff user
    if not job.user.is_staff:
        logger.error("User %s is not a staff user", job.user)
        raise OpenPortalException(f"User {job.user} is not a staff user")

    try:
        op_job = client.run(job.command)
    except OpenPortalException as e:
        logger.error("Failed to run command %s: %s", job.command, e)
        raise e

    job.report.clear()
    job.state = Job.States.CREATING
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
        job.report = op_job.error_message

    elif op_job.is_finished:
        job.state = Job.States.OK
        job.report = op_job.result

    job.save()



def get_user_allocations(user):
    connected_projects = get_connected_projects(user)
    connected_customers = get_connected_customers(user)

    project_allocations = models.Allocation.objects.filter(
        is_active=True, project__in=connected_projects
    )

    customer_allocations = models.Allocation.objects.filter(
        is_active=True, project__customer__in=connected_customers
    )

    return (project_allocations, customer_allocations)


def get_profile_allocations(profile):
    return itertools.chain(*get_user_allocations(profile.user))


def sanitize_allocation_name(name):
    incorrect_symbols_regex = r"[^%s]+" % models.OPENPORTAL_ALLOCATION_REGEX
    return re.sub(incorrect_symbols_regex, "", name)
