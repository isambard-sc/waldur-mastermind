from django.conf import settings
from django.db import models

from waldur_core.structure.models import BaseResource


class Job(BaseResource):
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
        on_delete=models.CASCADE,
        to=settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
    )

    report = models.JSONField(
        verbose_name="Job output",
        help_text="Output of the job",
        blank=True,
        null=True,
    )

    @classmethod
    def get_url_name(cls):
        return "openportal-job"
