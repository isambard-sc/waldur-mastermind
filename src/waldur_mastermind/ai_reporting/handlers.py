def on_reporting_file_deleted(sender, instance, **kwargs):
    # The file is a row in the media table that only this ReportingFile points
    # to, so it would outlive the row as an orphaned copy nobody can reach.
    # Bulk QuerySet.delete() (used by the retention cleanup tasks) still fires
    # post_delete per instance, so this also runs for those, not just a single
    # instance.delete() call. Same idiom as
    # waldur_mastermind.matrix_chat.handlers.on_history_export_deleted.
    if instance.file:
        instance.file.delete(save=False)
