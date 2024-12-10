import re

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils import FieldTracker

from waldur_core.core import models as core_models
from waldur_core.structure import models as structure_models
from waldur_openportal import utils

MAX_OP_USERNAME_LENGTH = 64

class Job(structure_models.BaseResource):
    """
    This model represents a single job that is being run via OpenPortal.
    A job is, e.g. an instruction to add or remove a user from a project,
    create new instances of platforms etc.
    """

    @classmethod
    def get_service_name(cls):
        return "OpenPortal"

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
    report = models.TextField("Job output", blank=True, null=True)
    runtime_state = models.CharField(max_length=32, blank=True)

    @classmethod
    def get_url_name(cls):
        return "openportal-job"


class UsageMixin(models.Model):
    class Meta:
        abstract = True

    node_usage = models.BigIntegerField(default=0)


class Allocation(UsageMixin, structure_models.BaseResource):
    is_active = models.BooleanField(default=True)
    tracker = FieldTracker()

    node_limit = models.BigIntegerField(default=0)

    @classmethod
    def get_url_name(cls):
        return "openportal-allocation"

    def usage_changed(self):
        return any(self.tracker.has_changed(field) for field in utils.FIELD_NAMES)

    def op_project_name(self):
        return self.backend_id

    @classmethod
    def get_backend_fields(cls):
        return super().get_backend_fields() + (
            "node_usage",
        )


class Association(core_models.UuidMixin):
    allocation = models.ForeignKey(
        to=Allocation,
        on_delete=models.CASCADE,
        related_name="op-associations-allocation+"
    )
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="op-associations-user+"
    )
    username = models.CharField(
        max_length=MAX_OP_USERNAME_LENGTH,
    )

    def op_project_name(self):
        return self.allocation.op_project_name()

    def op_user_name(self):
        return self.username

    def __str__(self):
        return f"{self.allocation.name} <-> {self.username}"


class AllocationUserUsage(UsageMixin):
    """
    Allocation usage per user. This model is responsible for the allocation usage definition for particular user.
    """

    allocation = models.ForeignKey(to=Allocation, on_delete=models.CASCADE, related_name="op-allocationuser-allocation+")
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )

    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        related_name="op-allocationuser-user+",
        on_delete=models.CASCADE,
        blank=True,
        null=True
    )

    username = models.CharField(max_length=MAX_OP_USERNAME_LENGTH)

    def __str__(self):
        return f"{self.username}: {self.allocation.name}"

    def __repr__(self) -> str:
        return self.__str__()
