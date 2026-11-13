def on_reporting_file_deleted(sender, instance, **kwargs):
    # Otherwise the stored file would be left behind with nothing pointing
    # to it. Also runs for the cleanup tasks' bulk deletes.
    if instance.file:
        instance.file.delete(save=False)
