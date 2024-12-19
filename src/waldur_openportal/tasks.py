import logging
import datetime
import time

from celery import shared_task

from waldur_core.core import utils as core_utils
from waldur_core.structure import models as structure_models
from waldur_core.structure.exceptions import ServiceBackendNotImplemented

from . import backend, models, utils
from .client import OpenPortalRunner, OpenPortalError


logger = logging.getLogger(__name__)


@shared_task(name="waldur_openportal.sync")
def sync():
    logger.info("OpenPortal task.sync")

    try:
        runner = OpenPortalRunner()
    except OpenPortalError as e:
        logger.error("Failed to connect to OpenPortal: %s", e)
        return

    runner.health()

    # find all of the jobs that are in pending state
    jobs = models.Job.objects.filter(state__in=[
                                         models.Job.States.CREATION_SCHEDULED,
                                         models.Job.States.CREATING,
                                         models.Job.States.UPDATE_SCHEDULED,
                                         models.Job.States.UPDATING])

    logger.info("Found %d jobs in unfinished state", len(jobs))

    for job in jobs:
        try:
            op_job = runner.get(job.backend_id)
        except OpenPortalError as e:
            logger.error("Failed to get job %s: %s", job.backend_id, e)
            job.state = models.Job.States.ERRED
            job.report = str(e)
            job.save()
            continue

        op_job.update()

        if op_job.is_error:
            logger.error("Job %s has failed: %s", job.backend_id, op_job.error_message)
            job.state = models.Job.States.ERRED
            job.report = op_job.error_message
            job.save()
        elif op_job.is_finished:
            logger.info("Job %s has finished: %s", job.backend_id, job.result)
            job.state = models.Job.States.OK
            job.report = op_job.result
            job.save()


def submit_job(job):
    try:
        runner = OpenPortalRunner()
    except OpenPortalError as e:
        logger.error("Failed to connect to OpenPortal: %s", e)
        raise e

    # make sure that the job is in the "CREATION_SCHEDULED" state
    if job.state != models.Job.States.CREATION_SCHEDULED:
        logger.error(f"Job {job} is not in the 'CREATION_SCHEDULED' state - state: {job.state}")
        raise OpenPortalError("Job is not in the 'CREATION_SCHEDULED' state")

    # make sure that the user submitting the job is a staff user
    if not job.user.is_staff:
        logger.error("User %s is not a staff user", job.user)
        raise OpenPortalError(f"User {job.user} is not a staff user")

    try:
        op_job = runner.run(job.command)
    except OpenPortalError as e:
        logger.error("Failed to run command %s: %s", job.command, e)
        raise e

    job.report.clear()
    job.state = models.Job.States.CREATING
    job.backend_id = op_job.uid

    # give it 2 seconds to complete before passing to
    # a long running celery task to monitor
    now = datetime.datetime.now()
    op_job.update()

    while not op_job.is_finished and datetime.datetime.now() - now < datetime.timedelta(seconds=2):
        time.sleep(0.1)
        op_job.update()

    if op_job.is_error:
        job.state = models.Job.States.ERRED
        job.report = op_job.error_message

    elif op_job.is_finished:
        job.state = models.Job.States.OK
        job.report = op_job.result

    job.save()

    return job


def get_structure_allocations(structure):
    if isinstance(structure, structure_models.Project):
        return list(models.Allocation.objects.filter(is_active=True, project=structure))
    elif isinstance(structure, structure_models.Customer):
        return list(
            models.Allocation.objects.filter(
                is_active=True, project__customer=structure
            )
        )
    else:
        return []


@shared_task(name="waldur_openportal.update_user")
def update_user(serialized_profile):
    logger.info(f"task.update_user: {serialized_profile}")
    profile = core_utils.deserialize_instance(serialized_profile)
    for allocation in utils.get_profile_allocations(profile):
        # adding and updating are the same thing in OpenPortal
        allocation.get_backend().add_user(allocation, profile.user)


@shared_task(name="waldur_openportal.delete_user")
def delete_user(serialized_profile):
    logger.info(f"task.delete_user: {serialized_profile}")
    profile = core_utils.deserialize_instance(serialized_profile)
    for allocation in utils.get_profile_allocations(profile):
        allocation.get_backend().delete_user(allocation, profile.user)


@shared_task(name="waldur_openportal.sync_allocation_users")
def sync_allocation_users(serialized_allocation):
    logger.info(f"task.sync_allocation_users: {serialized_allocation}")
    allocation = core_utils.deserialize_instance(serialized_allocation)
    openportal_backend: backend.OpenPortalBackend = allocation.get_backend()
    openportal_backend.sync_users(allocation)


@shared_task(name="waldur_openportal.schedule_sync")
def schedule_sync():
    logger.info("OpenPortal task.schedule_sync")
    for customer in structure_models.Customer.objects.all():
        for allocation in get_structure_allocations(customer):
            sync_allocation_users.delay(core_utils.serialize_instance(allocation))
