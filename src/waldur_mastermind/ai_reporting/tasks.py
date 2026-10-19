import logging

import requests
from celery import shared_task
from django.conf import settings

from waldur_mastermind.ai_reporting.models import ReportingMessage

logger = logging.getLogger(__name__)

# Generous but bounded - run_agent.run() can take minutes across many tool-use
# turns (see harness_manual_loop/run_agent.py's MAX_TURNS), but a hung harness
# call must not tie up a Celery worker slot forever.
_HARNESS_REQUEST_TIMEOUT_SECONDS = 600


@shared_task(name="waldur_mastermind.ai_reporting.ask_harness")
def ask_harness(message_id: int, new_session: bool = False):
    """Call the AI reporting harness for one ReportingMessage and record the result.

    Runs in a Celery worker, not a web request - this is what lets run() take
    minutes without tying up a Django web worker (see the design discussion in
    PROJECT_LOG.md / this app's docstrings for why).
    """
    try:
        message = ReportingMessage.objects.select_related("session__user").get(
            pk=message_id
        )
    except ReportingMessage.DoesNotExist:
        logger.error("ask_harness: ReportingMessage %s does not exist", message_id)
        return

    user = message.session.user

    try:
        response = requests.post(
            f"{settings.AI_REPORTING_HARNESS_URL}/query",
            headers={"X-Waldur-User-Id": str(user.uuid)},
            json={"prompt": message.prompt, "new_session": new_session},
            timeout=_HARNESS_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        logger.exception(
            "ask_harness: request to the harness failed for message %s", message_id
        )
        message.status = ReportingMessage.Status.FAILED
        message.error_message = str(exc)
        message.save(update_fields=["status", "error_message", "modified"])
        return
    except ValueError:
        logger.exception(
            "ask_harness: harness returned a non-JSON response for message %s",
            message_id,
        )
        message.status = ReportingMessage.Status.FAILED
        message.error_message = "The harness returned an unexpected response."
        message.save(update_fields=["status", "error_message", "modified"])
        return

    message.status = ReportingMessage.Status.DONE
    message.answer = payload.get("answer", "")
    message.new_files = payload.get("new_files", [])
    message.save(
        update_fields=["status", "answer", "new_files", "modified"]
    )
