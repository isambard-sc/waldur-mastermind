"""Who may download an archived document.

The prefixes here are deliberately *not* the live proposal app's
``call_documents`` / ``proposal_project_supporting_documentation``:
``access.register()`` raises on a duplicate prefix, and were the archive to share
them the live rule would answer for these files, query its own empty tables and
deny every one.  ``archive_old_proposals`` renames ``media_file.name`` onto these
prefixes as part of the copy.

Note also that upstream registers call documents as *public*.  Archived ones are
not: they follow §4.2 like everything else here.
"""

from waldur_core.media import access

from . import models, permissions

access.register(
    access.upload_prefix(models.ArchivedCallDocument, "file"),
    access.queryset_rule(
        models.ArchivedCallDocument, ["file"], permissions.filter_call_documents
    ),
)

access.register(
    access.upload_prefix(models.ArchivedProposalDocument, "file"),
    access.queryset_rule(
        models.ArchivedProposalDocument,
        ["file"],
        permissions.filter_proposal_documents,
    ),
)
