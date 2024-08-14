import logging
import time

from waldur_openportal.client import OpenPortalClient

from .models import OPJob

logger = logging.getLogger(__name__)


def pull_jobs(api_url, token, service_settings, project):
    client = OpenPortalClient(api_url, token)
    task_id = client.list_jobs()
    while True:
        task = client.get_task(task_id)
        if task["status"] in ["200", "400"]:
            break
        time.sleep(2)

    if task["status"] != "200":
        logger.warning("OpenPortal task %s has failed", task_id)
        return

    for job_details in task["data"]:
        job, created = OPJob.objects.update_or_create(
            service_settings=service_settings,
            project=project,
            backend_id=job_details["jobid"],
            defaults={
                "name": job_details["name"],
                "runtime_state": job_details["state"],
                "state": OPJob.States.OK,
            },
        )
        if created:
            logger.info(
                "SLURM job %s has been pulled from OpenPortal to project %s",
                job.backend_id,
                project.id,
            )


def submit_job(api_url, token, job):
    client = OpenPortalClient(api_url, token)
    task_id = client.submit_job(job.file.file)

    while True:
        task = client.get_task(task_id)
        if task["status"] in ["200", "400"]:
            break
        time.sleep(2)

    if task["status"] != "200":
        job.state = OPJob.States.ERRED
        job.error_message = task["data"]
        job.save()

    job_id = task["data"]["jobid"]
    job.backend_id = job_id
    job.report = task["data"]["result"]
    job.state = OPJob.States.OK
    job.save()
