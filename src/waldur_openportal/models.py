from django.conf import settings
from django.db import models

from waldur_core.structure.models import BaseResource


class Job(BaseResource):
    """
    This model represents a single job that is being run via OpenPortal.
    A job is, e.g. an instruction to add or remove a user from a project,
    create new instances of platforms etc.
    """

    @classmethod
    def get_service_name(cls):
        return "OPENPORTAL"

    command = models.TextField(
        help_text="Command being run via OpenPortal",
        blank=True,
        null=True,
    )
    user = models.ForeignKey(
        help_text="Reference to user which submitted job",
        related_name="op-jobs-user+",
        on_delete=models.CASCADE,
        to=settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
    )
    report = models.JSONField("Job output", blank=True, null=True)
    runtime_state = models.CharField(max_length=100, blank=True)

    @classmethod
    def get_url_name(cls):
        return "openportal-job"
