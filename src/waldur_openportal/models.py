from django.conf import settings
from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator

from waldur_core.core import models as core_models
from waldur_core.structure.models import BaseResource

from model_utils import FieldTracker

OPENPORTAL_ALLOCATION_REGEX = "a-zA-Z0-9-_"
OPENPORTAL_ALLOCATION_NAME_MAX_LEN = 34


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


class UsageMixin(models.Model):
    class Meta:
        abstract = True

    cpu_usage = models.BigIntegerField(default=0)
    ram_usage = models.BigIntegerField(default=0)
    gpu_usage = models.BigIntegerField(default=0)


class Allocation(UsageMixin, BaseResource):
    is_active = models.BooleanField(default=True)
    tracker = FieldTracker()

    cpu_limit = models.BigIntegerField(default=0)
    gpu_limit = models.BigIntegerField(default=0)
    ram_limit = models.BigIntegerField(default=0)

    @classmethod
    def get_url_name(cls):
        return "openportal-allocation"

    def usage_changed(self):
        from . import utils
        return any(self.tracker.has_changed(field) for field in utils.FIELD_NAMES)

    @classmethod
    def get_backend_fields(cls):
        return super().get_backend_fields() + (
            "cpu_usage",
            "gpu_usage",
            "ram_usage",
        )


class AllocationUserUsage(UsageMixin):
    """
    Allocation usage per user. This model is responsible for the allocation usage definition for particular user.
    """

    allocation = models.ForeignKey(to=Allocation, related_name="op-auu-allocation+", on_delete=models.CASCADE)
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )

    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, related_name="op-auu-user+", on_delete=models.CASCADE, blank=True, null=True
    )

    username = models.CharField(max_length=32)

    def __str__(self):
        return f"{self.username}: {self.allocation.name}"

    def __repr__(self) -> str:
        return self.__str__()



class Association(core_models.UuidMixin):
    allocation = models.ForeignKey(
        to=Allocation, on_delete=models.CASCADE, related_name="op-associations+"
    )

    def __str__(self):
        return f"{self.allocation.name} <-> {self.uuid}"
