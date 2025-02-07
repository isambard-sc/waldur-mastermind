import logging

from . import op as openportal

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core import validators

from model_utils import FieldTracker

from waldur_core.core import models as core_models
from waldur_core.structure import models as structure_models
from waldur_openportal import utils

logger = logging.getLogger(__name__)

MAX_USER_SHORTNAME_LENGTH = 32
MAX_PROJECT_SHORTNAME_LENGTH = 30
MAX_GROUPNAME_LENGTH = 64
MAX_USERNAME_LENGTH = 64
MAX_USERIDENTIFIER_LENGTH = 128
MAX_ALLOWED_DESTINATIONS_LENGTH = 1024


class UsageMixin(models.Model):
    class Meta:
        abstract = True

    # This is the number of node hours used
    node_usage = models.DecimalField(default=0, decimal_places=2, max_digits=20)


class Allocation(UsageMixin, structure_models.BaseResource):
    is_active = models.BooleanField(default=True)
    tracker = FieldTracker()

    node_limit = models.BigIntegerField(default=0)

    # The local group name for the group to which all members of the
    # allocation will be added (e.g. the Unix group)
    groupname = models.TextField(
        max_length=MAX_GROUPNAME_LENGTH,
        blank=True,
        null=True,
    )

    # Whether or not the project has been successfully added to OpenPortal
    is_added = models.BooleanField(default=False)

    @classmethod
    def get_url_name(cls):
        return "openportal-allocation"

    def is_added_to_openportal(self):
        return self.is_added

    def usage_changed(self):
        return any(self.tracker.has_changed(field) for field in utils.FIELD_NAMES)

    def has_local_group(self) -> bool:
        return bool(self.groupname)

    def get_local_group(self) -> str:
        return self.groupname

    def has_project_identifier(self) -> bool:
        return bool(self.backend_id)

    def set_project_identifier(self, project: openportal.ProjectIdentifier):
        if not isinstance(project, openportal.ProjectIdentifier):
            project = openportal.ProjectIdentifier(project)

        if self.has_project_identifier():
            if project != self.get_project_identifier():
                raise ValueError(
                    f"Project {project} does not match allocation {self.get_project_identifier()}"
                )

            return

        self.backend_id = str(project)

    def get_project_identifier(self) -> openportal.ProjectIdentifier:
        if not self.has_project_identifier():
            raise ValueError("ProjectIdentifier is not set!")

        return openportal.ProjectIdentifier(self.backend_id)

    def has_mapping(self) -> bool:
        return self.has_project_identifier() and self.has_local_group()

    def get_mapping(self) -> openportal.ProjectMapping:
        if not self.has_mapping():
            raise ValueError("ProjectMapping is not set!")

        return openportal.ProjectMapping(
            f"{self.get_project_identifier()}:{self.get_local_group()}"
        )

    def set_mapping(self, mapping: openportal.ProjectMapping):
        if not isinstance(mapping, openportal.ProjectMapping):
            mapping = openportal.ProjectMapping(mapping)

        self.set_project_identifier(mapping.project)
        self.groupname = mapping.local_group

    @classmethod
    def get_backend_fields(cls):
        return super().get_backend_fields() + ("node_usage",)

    def __str__(self):
        if self.has_mapping():
            return f"{self.name}|{self.get_mapping()}"
        elif self.has_project_identifier():
            return f"{self.name}|{self.get_project_identifier()}"
        else:
            return f"{self.name} (not in OpenPortal)"

    def __repr__(self):
        return self.__str__()


class Association(core_models.UuidMixin):
    # This is the allocation to which the user is associated.
    allocation = models.ForeignKey(
        to=Allocation,
        on_delete=models.CASCADE,
        related_name="op-associations-allocation+",
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

    # This is the local groupname on the instance being allocated
    # (e.g. the primary unix group for the user)
    groupname = models.CharField(
        max_length=MAX_GROUPNAME_LENGTH,
        blank=True,
        null=True,
    )

    # This is the OpenPortal UserIdentifier that uniquely
    # identifies this user in OpenPortal
    useridentifier = models.CharField(
        max_length=MAX_USERIDENTIFIER_LENGTH, blank=True, null=True
    )

    def has_project_identifier(self) -> bool:
        return self.allocation.has_project_identifier()

    def set_project_identifier(self, project: openportal.ProjectIdentifier):
        self.allocation.set_project_identifier(project)

    def get_project_identifier(self) -> openportal.ProjectIdentifier:
        return self.allocation.get_project_identifier()

    def has_user_identifier(self) -> bool:
        return bool(self.useridentifier)

    def set_user_identifier(self, user: openportal.UserIdentifier):
        if not isinstance(user, openportal.UserIdentifier):
            user = openportal.UserIdentifier(user)

        if self.has_user_identifier():
            if user != self.get_user_identifier():
                raise ValueError(
                    f"User {user} does not match association {self.get_user_identifier()}"
                )
        else:
            self.set_project_identifier(user.project_identifier)
            self.useridentifier = str(user)

    def get_user_identifier(self) -> openportal.UserIdentifier:
        return openportal.UserIdentifier(self.useridentifier)

    def has_local_group(self) -> bool:
        return bool(self.groupname)

    def get_local_group(self) -> str:
        return self.groupname

    def has_local_user(self) -> bool:
        return bool(self.username)

    def get_local_user(self) -> str:
        return self.username

    def has_mapping(self) -> bool:
        return (
            self.has_user_identifier()
            and self.has_local_user()
            and self.has_local_group()
        )

    def set_mapping(self, mapping: openportal.UserMapping):
        if not isinstance(mapping, openportal.UserMapping):
            mapping = openportal.UserMapping(mapping)

        self.set_user_identifier(mapping.user)

        if self.has_local_user():
            if mapping.local_user != self.get_local_user():
                logger.warning(
                    f"Changing local user from {self.username} to {mapping.local_user} for {self}"
                )

        self.username = mapping.local_user

        if self.has_local_group():
            if mapping.local_group != self.get_local_group():
                logger.warning(
                    f"Changing local group from {self.groupname} to {mapping.local_group} for {self}"

        self.groupname = mapping.local_group

    def get_mapping(self) -> openportal.UserMapping:
        if not self.has_user_identifier():
            raise ValueError("UserIdentifier is not set!")

        if not self.has_local_user():
            raise ValueError("Local user is not set!")

        return openportal.UserMapping(
            f"{self.get_user_identifier()}:{self.get_local_user()}:{self.get_local_group()}"
        )

    def __str__(self):
        if self.has_mapping():
            return f"{self.allocation} <-> {self.get_mapping()}"
        elif self.has_user_identifier():
            return f"{self.allocation} <-> {self.get_user_identifier()}"
        else:
            return f"{self.allocation} <-> {self.user} (not in OpenPortal)"

    def __repr__(self):
        return self.__str__()


class AllocationUserUsage(UsageMixin):
    """
    Allocation usage per user. This model is responsible for the allocation usage definition for particular user.
    """

    allocation = models.ForeignKey(
        to=Allocation,
        on_delete=models.CASCADE,
        related_name="op-allocationuser-allocation+",
    )
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )

    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        related_name="op-allocationuser-user+",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
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


class HistoricalAllocation(UsageMixin):
    """
    This model holds the historical usage of an allocation.
    It records the total usage per month, plus whether or not that
    month is "complete" (i.e. the report from OpenPortal is complete
    for that month, and no more usage will be added).
    """

    allocation = models.ForeignKey(
        to=Allocation, on_delete=models.CASCADE, related_name="op-historicalallocation+"
    )
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )
    is_complete = models.BooleanField(default=False)

    def __str__(self):
        if self.is_complete:
            return (
                f"{self.allocation.name} [{self.year}-{self.month}]: {self.node_usage}"
            )
        else:
            return f"{self.allocation.name} [{self.year}-{self.month}]: {self.node_usage} (incomplete)"

    def __repr__(self) -> str:
        return self.__str__()


class UserInfo(models.Model):
    """
    This model is responsible for storing additional user information
    required by OpenPortal. Currently this is the preferred shortname
    for the user, which will be combined with the project shortname
    to create the local username
    """

    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        related_name="op-userinfo-user+",
        on_delete=models.CASCADE,
    )

    shortname = models.CharField(
        verbose_name=_("shortname"),
        max_length=MAX_USER_SHORTNAME_LENGTH,
        unique=True,
        null=True,
        help_text=_(
            "A short, unique name for you. It will be used to form your local username on any systems. Should only contain lower-case letters and digits and must start with a letter."
        ),
        validators=[
            validators.RegexValidator(
                regex=r"^[a-z][a-z0-9]+$",
                message="Must start with a letter and only contain numbers and letters.",
            ),
            validators.RegexValidator(
                regex=r"(admin)|(root)$",
                inverse_match=True,
            ),
            validators.MinLengthValidator(4),
            validators.MaxLengthValidator(MAX_USER_SHORTNAME_LENGTH),
        ],
    )

    tracker = FieldTracker(fields=["shortname"])

    def __str__(self) -> str:
        return f"{self.user}: {self.shortname}"

    def __repr__(self) -> str:
        return self.__str__()

    def sanitise(self):
        """
        Double check that our shortname matches the user unix_username
        if this field exists
        """
        if hasattr(self.user, "unix_username"):
            if (
                self.shortname != self.user.unix_username
                and self.user.unix_username is not None
            ):
                self.set_shortname(self.user.unix_username)
                self.save()

    def set_shortname(self, shortname: str):
        """
        Set the shortname, checking whether or not this has not already
        been set, and making sure it lines up with the unix_username if
        that field is present in the user
        """
        if not shortname:
            raise ValueError("Shortname cannot be empty.")

        if hasattr(self.user, "unix_username"):
            if (
                shortname != self.user.unix_username
                and self.user.unix_username is not None
            ):
                self.user.unix_username = self.shortname
                self.user.save()

            self.shortname = self.user.unix_username

        if self.shortname and self.shortname != shortname:
            logger.error(
                f"Cannot change shortname of user {self.user} from {self.shortname} to {shortname}"
            )
            raise ValueError(
                f"Cannot change shortname of user {self.user} from {self.shortname} to {shortname}"
            )

        self.shortname = shortname

    def save(self, *args, **kwargs):
        if "update_fields" in kwargs and "query_field" not in kwargs["update_fields"]:
            kwargs["update_fields"] = set(kwargs["update_fields"]).add("query_field")

        # The shortname cannot be changed after creation as external systems may already depend on it.
        prev = self.tracker.previous("shortname")
        if self.tracker.has_changed("shortname") and prev:
            new = self.shortname
            raise ValueError(
                _(
                    f"Cannot change shortname of user ('{prev}' → '{new}') after creation."
                )
            )

        super().save(*args, **kwargs)


class ProjectInfo(models.Model):
    """
    This model is responsible for storing additional project information
    required by OpenPortal. Currently this is the shortname for the project,
    which will be combined with the user shortname to create the local
    username on a system. It also contains the list of allowable
    destinations of instances that can be attached to this project.
    For example, a project may only allow "brics.aip1.*", meaning that
    only instances that start with "brics.aip1." can be attached to
    this project.
    """

    project = models.OneToOneField(
        to=structure_models.Project,
        related_name="op-projectinfo-project+",
        on_delete=models.CASCADE,
    )

    shortname = models.CharField(
        verbose_name=_("shortname"),
        max_length=MAX_PROJECT_SHORTNAME_LENGTH,
        unique=True,
        null=True,
        help_text=_(
            "A short, unique name for the project. It will be used to form the local username of any users in the project on any systems. Should only contain lower-case letters and digits and must start with a letter."
        ),
        validators=[
            validators.RegexValidator(
                regex=r"^[a-z0-9\-_]+$",
            ),
            validators.RegexValidator(
                regex=r"(-admin)|(-root)$",
                inverse_match=True,
            ),
            validators.MinLengthValidator(3),
            validators.MaxLengthValidator(MAX_PROJECT_SHORTNAME_LENGTH),
        ],
    )

    # This is the list of allowable destinations of instances that can be attached to this project.
    # For example, a project may only allow "brics.aip1.*", meaning that only instances that start with
    # "brics.aip1." can be attached to this project.
    allowed_destinations = models.TextField(
        verbose_name=_("allowed destinations"),
        max_length=MAX_ALLOWED_DESTINATIONS_LENGTH,
        help_text=_(
            "A comma-separated list of allowable destinations of instances that \
             can be attached to this project. For example, a project may only allow \
             'brics.aip1.*', meaning that only instances that start with 'brics.aip1.' \
             can be attached to this project."
        ),
        blank=True,
        null=True,
    )

    tracker = FieldTracker(fields=["shortname", "allowed_destinations"])

    def __str__(self) -> str:
        return f"{self.project}: {self.shortname}"

    def __repr__(self) -> str:
        return self.__str__()

    def sanitise(self):
        """
        Double check that our shortname matches the project short_name
        if this field exists
        """
        if hasattr(self.project, "short_name"):
            if (
                self.shortname != self.project.short_name
                and self.project.short_name is not None
            ):
                self.set_shortname(self.project.short_name)
                self.save()

    def set_shortname(self, shortname: str):
        """
        Set the shortname, checking whether or not this has not already
        been set, and making sure it lines up with the short_name if
        that field is present in the project
        """
        if not shortname:
            raise ValueError("Shortname cannot be empty.")

        if hasattr(self.project, "short_name"):
            if (
                shortname != self.project.short_name
                and self.project.short_name is not None
            ):
                self.project.short_name = self.shortname
                self.project.save()

            self.shortname = self.project.short_name

        if self.shortname and self.shortname != shortname:
            logger.error(
                f"Cannot change shortname of project {self.project} from {self.shortname} to {shortname}"
            )
            raise ValueError(
                f"Cannot change shortname of project {self.project} from {self.shortname} to {shortname}"
            )

        self.shortname = shortname

    def set_allowed_destinations(self, destinations: str):
        """
        Set the allowed destinations of instances that can be attached to this project.
        This should be a comma-separated list of destinations.
        """
        if not destinations:
            self.allowed_destinations = None
        else:
            self.allowed_destinations = str(destinations)

    def save(self, *args, **kwargs):
        if "update_fields" in kwargs and "query_field" not in kwargs["update_fields"]:
            kwargs["update_fields"] = set(kwargs["update_fields"]).add("query_field")

        # The shortname cannot be changed after creation as external systems may already depend on it.
        prev = self.tracker.previous("shortname")
        if self.tracker.has_changed("shortname") and prev:
            new = self.shortname
            raise ValueError(
                _(
                    f"Cannot change shortname of project ('{prev}' → '{new}') after creation."
                )
            )

        super().save(*args, **kwargs)
