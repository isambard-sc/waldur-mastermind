from django.db import transaction

from waldur_mastermind.ai_reporting import tasks


def on_reporting_session_deleted(sender, instance, **kwargs):
    # The harness keeps the conversation's history and fetched data; delete
    # those too, whether retention or a user deletion removed it.
    user = getattr(instance, "user", None)
    if user is None:
        return
    user_uuid, session_uuid = str(user.uuid), str(instance.uuid)
    transaction.on_commit(
        lambda: tasks.delete_harness_session.delay(user_uuid, session_uuid)
    )


def on_reporting_file_deleted(sender, instance, **kwargs):
    # Otherwise the stored file would be left behind with nothing pointing
    # to it. Also runs for the cleanup tasks' bulk deletes.
    if instance.file:
        instance.file.delete(save=False)
