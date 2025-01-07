import re

from . import op as openportal

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from model_utils import FieldTracker

from waldur_core.core import models as core_models
from waldur_core.structure import models as structure_models
from waldur_openportal import utils

MAX_USERNAME_LENGTH = 32
MAX_OP_USER_LENGTH = 96

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

    def has_project_identifier(self) -> bool:
        return bool(self.backend_id)

    def set_project_identifier(self, project: openportal.ProjectIdentifier):
        if not isinstance(project, openportal.ProjectIdentifier):
            project = openportal.ProjectIdentifier(project)

        if self.has_project_identifier():
            if project != self.get_project_identifier():
                raise ValueError(f"Project {project} does not match allocation {self.op_project()}")

            return

        self.backend_id = str(project)

    def get_project_identifier(self) -> openportal.ProjectIdentifier:
        if not self.has_project_identifier():
            raise ValueError("ProjectIdentifier is not set!")

        return openportal.ProjectIdentifier(self.backend_id)

    @classmethod
    def get_backend_fields(cls):
        return super().get_backend_fields() + (
            "node_usage",
        )


class Association(core_models.UuidMixin):
    # This is the allocation to which the user is associated.
    allocation = models.ForeignKey(
        to=Allocation,
        on_delete=models.CASCADE,
        related_name="op-associations-allocation+"
    )
    # This is the Waldur user which is associated with the allocation.
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="op-associations-user+",
        blank=True,
        null=True,
    )

    # This is the local username on the instance being allocated
    # (e.g. the unix username)
    username = models.CharField(
        max_length=MAX_USERNAME_LENGTH,
        blank=True,
        null=True,
    )

    # This is the OpenPortal UserIdentifier that uniquely
    # identifies this user in OpenPortal
    op_user = models.CharField(
        max_length=MAX_OP_USER_LENGTH,
        blank=True,
        null=True
    )

    def has_project_identifier(self) -> bool:
        return self.allocation.has_project_identifier()

    def set_project_identifier(self, project: openportal.ProjectIdentifier):
        self.allocation.set_project_identifier(project)

    def get_project_identifier(self) -> openportal.ProjectIdentifier:
        return self.allocation.get_project_identifier()

    def has_user_identifier(self) -> bool:
        return bool(self.op_user)

    def set_user_identifier(self, user: openportal.UserIdentity):
        if not isinstance(user, openportal.UserIdentity):
            user = openportal.UserIdentifier(user)

        if self.has_user_identifier():
            if user != self.get_op_user():
                raise ValueError(f"User {user} does not match association {self.op_user()}")

            return

        self.set_project_identifier(user.project_identifier)
        self.op_user = str(user)

    def get_user_identifier(self) -> openportal.UserIdentifier:
        return openportal.UserIdentifier(self.username)

    def has_local_user(self) -> bool:
        return bool(self.username)

    def get_local_user(self) -> str:
        return self.username

    def has_mapping(self) -> bool:
        return self.has_user_identifier() and self.has_local_user()

    def set_mapping(self, mapping: openportal.UserMapping):
        if not isinstance(mapping, openportal.UserMapping):
            mapping = openportal.UserMapping(mapping)

        self.set_user_identifier(mapping.user)

        if self.has_local_user():
            if mapping.local_user != self.get_local_user():
                raise ValueError(f"Local user {mapping.local_user} does not match association {self.username}")

            return

        self.username = mapping.local_user

    def get_mapping(self) -> openportal.UserMapping:
        if not self.has_user_identifier():
            raise ValueError("UserIdentifier is not set!")

        if not self.has_local_user():
            raise ValueError("Local user is not set!")

        return openportal.UserMapping(f"{self.get_op_user()}:{self.get_local_user()}")

    def __str__(self):
        return f"{self.allocation.name} <-> {self.mapping}"


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

    # This is the local username on the instance being allocated
    # (e.g. the unix username). We can work out the OpenPortal UserIdentifier
    # from the allocation and user objects, and then the OpenPortal
    # UserMapping from that.
    username = models.CharField(max_length=MAX_USERNAME_LENGTH)

    def __str__(self):
        return f"{self.username}: {self.allocation.name}"

    def __repr__(self) -> str:
        return self.__str__()
