import logging

from . import op as openportal

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import F
from django.utils.translation import gettext_lazy as _
from django.core import validators

from model_utils import FieldTracker

from waldur_core.core import models as core_models
from waldur_core.structure import models as structure_models
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_openportal import utils

logger = logging.getLogger(__name__)

MAX_USER_SHORTNAME_LENGTH = 32
MAX_PROJECT_SHORTNAME_LENGTH = 30
MAX_GROUPNAME_LENGTH = 64
MAX_USERNAME_LENGTH = 64
MAX_USERIDENTIFIER_LENGTH = 128
MAX_PROJECTIDENTIFIER_LENGTH = 64
MAX_PORTALIDENTIFIER_LENGTH = 32
MAX_PROJECTCLASS_LENGTH = 128
MAX_ALLOWED_DESTINATIONS_LENGTH = 1024


class OnceTask(models.Model):
    """
    This model is responsible for storing data about tasks that should
    only be run once, e.g. to create a project class or an allocation.
    """

    task_name = models.CharField(
        max_length=128, unique=True, verbose_name=_("task name"), db_index=True
    )

    # The date when this task was started
    last_run = models.DateTimeField(
        verbose_name=_("run date"),
        help_text=_("The date when this task was started."),
        blank=True,
        null=True,
    )

    def __str__(self) -> str:
        return self.task_name

    def __repr__(self) -> str:
        return self.__str__()


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


class RemoteAllocation(UsageMixin, structure_models.BaseResource):
    is_active = models.BooleanField(default=True)
    tracker = FieldTracker()

    node_limit = models.BigIntegerField(default=0)

    # The ProjectIdentifier for the project in the remote OpenPortal instance
    remote_project_identifier = models.CharField(
        max_length=MAX_PROJECTIDENTIFIER_LENGTH,
        blank=True,
        null=True,
        verbose_name=_("remote project identifier"),
        help_text=_("The identifier of the project in the remote OpenPortal instance."),
    )

    # Whether or not the project has been successfully added to OpenPortal
    is_added = models.BooleanField(default=False)

    @classmethod
    def get_url_name(cls):
        return "openportal-remote-allocation"

    def is_added_to_openportal(self):
        return self.is_added

    def usage_changed(self):
        return any(self.tracker.has_changed(field) for field in utils.FIELD_NAMES)

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
        return self.has_project_identifier() and self.has_remote_project_identifier()

    def get_mapping(self) -> openportal.ProjectMapping:
        if not self.has_mapping():
            raise ValueError("ProjectMapping is not set!")

        return openportal.ProjectMapping(
            f"{self.get_project_identifier()}:{self.get_remote_project_identifier()}"
        )

    def has_remote_project_identifier(self) -> bool:
        return self.remote_project_identifier is not None

    def set_remote_project_identifier(
        self, remote_project: openportal.ProjectIdentifier
    ):
        if not isinstance(remote_project, openportal.ProjectIdentifier):
            remote_project = openportal.ProjectIdentifier(remote_project)

        if self.has_remote_project_identifier():
            if remote_project != self.get_remote_project_identifier():
                raise ValueError(
                    f"Remote project {remote_project} does not match allocation {self.get_remote_project_identifier()}"
                )

            return

        self.remote_project_identifier = str(remote_project)

    def set_mapping(self, mapping: openportal.ProjectMapping):
        if not isinstance(mapping, openportal.ProjectMapping):
            mapping = openportal.ProjectMapping(mapping)

        self.set_project_identifier(mapping.project)
        self.set_remote_project_identifier(mapping.local_group)

    @classmethod
    def get_backend_fields(cls):
        return super().get_backend_fields() + ("node_usage",)

    def get_backend(self, **kwargs):
        from .remotebackend import RemoteOpenPortalBackend

        return RemoteOpenPortalBackend(self.service_settings, **kwargs)

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
                )

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


class RemoteAssociation(core_models.UuidMixin):
    # This is the allocation to which the user is associated.
    allocation = models.ForeignKey(
        to=RemoteAllocation,
        on_delete=models.CASCADE,
        related_name="op-remote_associations-remote_allocation+",
    )

    # This is the Waldur user which is associated with the allocation.
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="op-remote_associations-user+",
        blank=True,
        null=True,
    )

    def __str__(self):
        return f"{self.allocation} <-> {self.user}"

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


class RemoteAllocationUserUsage(UsageMixin):
    """
    Allocation usage per user. This model is responsible for the allocation usage definition for particular user.
    """

    allocation = models.ForeignKey(
        to=RemoteAllocation,
        on_delete=models.CASCADE,
        related_name="op-remote-allocationuser-remote-allocation+",
    )
    year = models.PositiveSmallIntegerField()
    month = models.PositiveSmallIntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(12)]
    )

    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        related_name="op-remote-allocationuser-user+",
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )

    def __str__(self):
        return f"{self.user}: {self.allocation.name}"

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


class HistoricalRemoteAllocation(UsageMixin):
    """
    This model holds the historical usage of an allocation.
    It records the total usage per month, plus whether or not that
    month is "complete" (i.e. the report from OpenPortal is complete
    for that month, and no more usage will be added).
    """

    allocation = models.ForeignKey(
        to=RemoteAllocation,
        on_delete=models.CASCADE,
        related_name="op-remote-historicalallocation+",
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


class ProjectShortNameGenerator(models.Model):
    """
    This model is responsible for generating unique shortnames for projects.
    It keeps track of the last used shortname and increments it for the next
    project.
    """

    shortname = models.CharField(
        max_length=MAX_PROJECT_SHORTNAME_LENGTH,
        verbose_name=_("shortname"),
        unique=True,
        help_text=_("The key / descriptor used to identify this generator."),
    )

    count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("count"),
        help_text=_("The number of projects created with this shortname."),
    )

    def __str__(self) -> str:
        return f"{self.shortname}: Count = {self.count}"

    def __repr__(self) -> str:
        return self.__str__()

    def increment_count(self):
        """
        Increment the count of projects created with this shortname.
        """
        self.count = F("count") + 1
        self.save(update_fields=["count"])
        self.refresh_from_db()

    def get_shortname(self) -> str:
        """
        Get the shortname for the current value of count.
        """

        # turn the number into a letter, e.g. 0 -> a, 1 -> b, ..., 25 -> z,
        # 26 -> aa, 27 -> ab, etc.
        count = int(self.count)

        if count < 0:
            raise ValueError("Count cannot be negative.")

        shortname = ""
        while count >= 0:
            shortname = chr((count % 26) + ord("a")) + shortname
            count = count // 26 - 1

        return self.shortname.replace("{count}", shortname)


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
        Enforce that the shortname set here is copied back to the
        project short_name field, if such a field exists
        (it will be removed in the future)
        """
        if hasattr(self.project, "short_name"):
            if self.shortname is None and self.project.short_name is not None:
                # copy if from the project (for legacy projects)
                self.shortname = self.project.short_name
                self.save()
            elif self.shortname is not None:
                # copy to the project so that it matches
                if self.project.short_name is None:
                    self.project.short_name = self.shortname
                    self.project.save()
                else:
                    if self.shortname != self.project.short_name:
                        logger.warning(
                            f"Project {self.project} has a different short_name ({self.project.short_name}) than the one set in OpenPortal ({self.shortname})."
                        )

                    self.project.short_name = self.shortname
                    self.project.save()

        if self.shortname is None:
            # Raise an error as we don't have a shortname set!
            raise ValueError(
                "Project shortname cannot be empty. Please set it in OpenPortal."
            )

    def set_shortname(self, shortname: str, force: bool = False):
        """
        Set the shortname, checking whether or not this has not already
        been set - note that it cannot be changed after creation
        as external systems may already depend on it.

        Only use 'force=True' if you are sure that you want to
        change the shortname, as this will bypass the checks
        """
        if not shortname:
            raise ValueError("Shortname cannot be empty.")

        shortname = shortname.strip()

        if len(shortname) == 0 or len(shortname) > MAX_PROJECT_SHORTNAME_LENGTH:
            raise ValueError(
                f"Shortname must be between 1 and {MAX_PROJECT_SHORTNAME_LENGTH} characters long."
            )

        self.shortname = shortname
        self.save(force_accept_changed_shortname=force)
        self.sanitise()

    def generate_shortname(self, generator: ProjectShortNameGenerator) -> str:
        """
        Generate a shortname using the provided generator.
        This will generate a unique shortname based on the
        rules in the generator
        """
        if self.shortname is not None:
            logger.warning(
                f"Project {self.project} already has a shortname set ({self.shortname})."
                " Not generating a new one."
            )
            return self.shortname

        if not isinstance(generator, ProjectShortNameGenerator):
            raise ValueError(
                "Generator must be an instance of ProjectShortNameGenerator"
            )

        while True:
            shortname = generator.get_shortname()

            try:
                self.set_shortname(shortname, force=True)
                return shortname
            except Exception as e:
                logger.warning(
                    f"Failed to set shortname {shortname} - is it already taken? {e}"
                )

            # If we fail, check that this was because the shortname
            # was already taken, and if so, increment the generator
            # and try again.
            projects = ProjectInfo.objects.filter(
                shortname=shortname,
            )

            if projects.exists():
                logger.warning(
                    f"Shortname {shortname} already exists. Incrementing generator."
                )
                generator.increment_count()
            else:
                logger.error(
                    f"Failed to generate shortname {shortname} for project {self.project}. "
                    "This should not happen, please check the generator."
                )
                raise ValueError(
                    f"Failed to generate shortname {shortname} for project {self.project}."
                )

    def set_allowed_destinations(self, destinations: str):
        """
        Set the allowed destinations of instances that can be attached to this project.
        This should be a comma-separated list of destinations.
        """
        if not destinations:
            self.allowed_destinations = None
        else:
            self.allowed_destinations = str(destinations)

    def save(self, *args, force_accept_changed_shortname: bool = False, **kwargs):
        if "update_fields" in kwargs and "query_field" not in kwargs["update_fields"]:
            kwargs["update_fields"] = set(kwargs["update_fields"]).add("query_field")

        # The shortname cannot be changed after creation as external systems may already depend on it.
        if not force_accept_changed_shortname:
            prev = self.tracker.previous("shortname")
            if self.tracker.has_changed("shortname") and prev:
                new = self.shortname
                raise ValueError(
                    _(
                        f"Cannot change shortname of project ('{prev}' → '{new}') after creation."
                    )
                )

        super().save(*args, **kwargs)


class ProjectNotification(models.Model):
    """
    This model is responsible for storing data about when and how often
    members of a project should be sent notifications about the current
    spending of the project and the end date.

    This is here rather than in invoices or notifications as our notification
    needs are quite bespoke, we will use data that comes directly from
    OpenPortal, and we need to isolate this code from the evolution of the
    rest of Waldur. Note that we could migrate this functionality into
    core Waldur if desired.
    """

    # Which project does this relate to?
    project = models.OneToOneField(
        to=structure_models.Project,
        related_name="op-projectnotification-project+",
        on_delete=models.CASCADE,
    )

    # How many days between notifications (0 = no notifications)
    # We default to sending notifications every fortnight
    frequency = models.PositiveSmallIntegerField(
        verbose_name=_("frequency"),
        default=14,
        help_text=_("How many days between notifications (0 = no notifications)."),
    )

    # When was the last notification sent?
    # This is a date, not a datetime, as we don't care about the time
    # of the notification, just the date.
    last_notification = models.DateField(
        verbose_name=_("last notification"),
        blank=True,
        null=True,
        help_text=_("When was the last notification sent?"),
    )

    def __str__(self) -> str:
        return f"{self.project}: Last notification {self.last_notification}, frequency {self.frequency}"

    def __repr__(self) -> str:
        return self.__str__()


class Job(models.Model):
    """
    This model is responsible for storing data about jobs that are
    running in OpenPortal. This is used to track the progress of jobs
    and to ensure that we don't run the same job multiple times.
    """

    job_id = models.CharField(
        max_length=36, unique=True, verbose_name=_("ID"), db_index=True
    )

    job_data = models.TextField(
        verbose_name=_("job data"),
        help_text=_("JSON representation of the job"),
        blank=True,
        null=True,
    )

    class State(models.TextChoices):
        PENDING = "pending", _("Pending")
        RUNNING = "running", _("Running")
        COMPLETED = "completed", _("Completed")
        COMMUNICATED = "communicated", _("Communicated")
        CANCELLED = "cancelled", _("Cancelled")

    state = models.CharField(
        max_length=20,
        choices=State.choices,
        default=State.PENDING,
        verbose_name=_("status"),
        help_text=_("The current status of the job."),
    )

    # record the date when this job was created
    created = models.DateField(
        auto_now_add=True,
        verbose_name=_("created"),
        help_text=_("The date when this job was created."),
    )

    def get_job(self) -> openportal.Job:
        """
        Get the job object from the job data.
        If the job data is not set, return None.
        """
        return openportal.Job.from_json(self.job_data)

    def __str__(self) -> str:
        try:
            j = openportal.Job.from_json(self.job_data)
            return str(j)
        except Exception as e:
            logger.error(f"Failed to parse job data for job {self.job_id}: {e}")
            return f"Job {self.job_id}: Invalid data"

    def __repr__(self) -> str:
        return self.__str__()


class ProjectClass(models.Model):
    """
    This model is responsible for storing data about project classes.
    A ProjectClass represents a category or type of project that can
    be created via OpenPortal. It is up to Waldur to map the ProjectClass
    combined with the calling portal to the Organisation that the project
    should be created in. In addition, the ProjectClass controls
    which portals can create which types of projects.
    """

    # The name of the project class, e.g. "isambard-ai"
    name = models.CharField(
        max_length=MAX_PROJECTCLASS_LENGTH, verbose_name=_("name"), db_index=True
    )

    # The name of the portal (PortalIdentifier) that is allowed to create
    # this project class. The combination of name and portal must be unique.
    portal = models.CharField(
        max_length=MAX_PORTALIDENTIFIER_LENGTH, verbose_name=_("portal"), db_index=True
    )

    # The customer (organisation) in which to place projects which are created in
    # this project class by the specified portal.
    customer = models.ForeignKey(
        to=structure_models.Customer,
        on_delete=models.CASCADE,
        related_name="op-projectclass-organisation+",
        verbose_name=_("organisation"),
        help_text=_("The organisation that this project class belongs to."),
    )

    # The shortname naming scheme for projects created in this class
    # by the specified portal. This should have "{year}" which will replaced
    # by the last digit of the current year, and "{count}", which will be
    # replaced by a letter (a, b, c, ..., z, aa, ab, ..., az, ba, bb, ...),
    # for example, "a{year}{count}" would become "a5a", "a5b", "a5c", etc.
    shortname = models.CharField(
        max_length=MAX_PROJECT_SHORTNAME_LENGTH,
        verbose_name=_("shortname"),
        null=True,
        blank=True,
    )

    # The list of MarketPlace Offerings that should be created automatically
    # for projects created in this class by the specified portal.
    offerings = models.ManyToManyField(
        marketplace_models.Offering,
        related_name="op-projectclass-offerings+",
        verbose_name=_("offerings"),
        help_text=_(
            "The list of MarketPlace Offerings that should be created automatically for projects created in this class by the specified portal."
        ),
    )

    # Combination of name and portal must be unique
    class Meta:
        unique_together = ("name", "portal")
        verbose_name = _("Project Class")
        verbose_name_plural = _("Project Classes")

    def __str__(self) -> str:
        return f"{self.portal} <=> {self.name}"

    def __repr__(self) -> str:
        return self.__str__()

    def get_generator(self) -> ProjectShortNameGenerator:
        """
        Get the ProjectShortNameGenerator for this project class.
        If it does not exist, create it.
        """
        if self.shortname is None:
            raise ValueError(
                "Project class shortname is not set. Please set it before generating a shortname."
            )

        shortname = self.shortname.strip()

        if len(shortname) == 0:
            raise ValueError("Project class shortname cannot be empty.")

        # Now replace the {year} with the last digit of the current year,
        # e.g. "myproject-{year}" becomes "myproject-5" for 2025.
        if "{year}" in shortname:
            from datetime import datetime

            current_year = datetime.now().year
            shortname = shortname.replace("{year}", str(current_year % 10))

        # Get (or create if needed) a new ProjectShortNameGenerator
        # for this year
        generator, created = ProjectShortNameGenerator.objects.get_or_create(
            shortname=shortname
        )

        if created:
            logger.info(f"Created new ProjectShortNameGenerator: {generator}")

        return generator


class ManagedProject(models.Model):
    """
    This model is responsible for storing data about projects that are
    managed by OpenPortal. This is used to track the progress of projects
    and to ensure that we don't create the same project multiple times.
    """

    # This is the OpenPortal ProjectIdentifier from the portal that
    # requested and manages this project
    identifier = models.CharField(
        max_length=MAX_PROJECTIDENTIFIER_LENGTH,
        unique=True,
        verbose_name=_("ID"),
        db_index=True,
    )

    # This is the JSON representation of the OpenPortal ProjectDetails
    # that is synced between this portal and the managing portal
    details = models.TextField(
        verbose_name=_("project data"),
        help_text=_("JSON representation of the project"),
        blank=True,
        null=True,
    )

    # This is the actual project in this Waldur
    project = models.ForeignKey(
        to=structure_models.Project,
        on_delete=models.CASCADE,
        related_name="op-managedproject-project+",
        verbose_name=_("project"),
        blank=True,
        null=True,
    )

    # This is the ProjectClass that this project belongs to.
    project_class = models.ForeignKey(
        to=ProjectClass,
        on_delete=models.CASCADE,
        related_name="op-managedproject-projectclass+",
        verbose_name=_("project class"),
        blank=True,
        null=True,
    )

    # This is the ProjectIdentifier for this project in this portal
    local_identifier = models.CharField(
        max_length=MAX_PROJECTIDENTIFIER_LENGTH,
        verbose_name=_("local ID"),
        blank=True,
        null=True,
        help_text=_("The local project identifier in this portal."),
    )

    def get_local_identifier(self) -> openportal.ProjectIdentifier:
        """
        Get the local ProjectIdentifier for this project.
        If the local identifier is not set, raise an error.
        """
        if not self.local_identifier:
            raise ValueError("Local identifier is not set for this project.")
        return openportal.ProjectIdentifier(self.local_identifier)

    def get_remote_identifier(self) -> openportal.ProjectIdentifier:
        """
        Get the remote ProjectIdentifier for this project.
        If the identifier is not set, raise an error.
        """
        if not self.identifier:
            raise ValueError("Remote identifier is not set for this project.")
        return openportal.ProjectIdentifier(self.identifier)

    def get_mapping(self) -> openportal.ProjectMapping:
        """
        Get the ProjectMapping object for this project.
        If the project data is not set, raise an error.
        """
        return openportal.ProjectMapping(
            f"{self.get_remote_identifier()}:{self.get_local_identifier()}"
        )

    def get_details(self) -> openportal.ProjectDetails:
        """
        Get the ProjectDetails object from the project data.
        If the project data is not set, return None.
        """
        return openportal.ProjectDetails.from_json(self.details)

    def get_default_offerings(self) -> list[marketplace_models.Offering]:
        """
        Get the default marketplace offerings for this project.
        If the project class is not set, return an empty list.
        """
        if self.project_class and self.project_class.offerings.exists():
            return list(self.project_class.offerings.all())
        else:
            return []

    def __str__(self) -> str:
        return f"ManagedProject {self.identifier} => {self.project}"

    def __repr__(self) -> str:
        return self.__str__()
