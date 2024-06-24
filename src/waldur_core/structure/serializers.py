import logging
from functools import lru_cache

import pyvat
from django.conf import settings
from django.contrib import auth
from django.contrib.contenttypes.models import ContentType
from django.core import exceptions as django_exceptions
from django.db import models as django_models
from django.db import transaction
from django.db.models import Q
from django.template.loader import get_template
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers
from rest_framework.authtoken import models as authtoken_models

from waldur_core.core import fields as core_fields
from waldur_core.core import models as core_models
from waldur_core.core import serializers as core_serializers
from waldur_core.core.clean_html import clean_html
from waldur_core.core.fields import MappedChoiceField
from waldur_core.media.serializers import ProtectedMediaSerializerMixin
from waldur_core.permissions.enums import SYSTEM_CUSTOMER_ROLES, PermissionEnum
from waldur_core.permissions.models import UserRole
from waldur_core.permissions.serializers import PermissionSerializer
from waldur_core.permissions.utils import get_permissions, has_permission
from waldur_core.structure import models, utils
from waldur_core.structure.filters import filter_visible_users
from waldur_core.structure.managers import (
    count_customer_users,
    filter_queryset_for_user,
)
from waldur_core.structure.models import CUSTOMER_DETAILS_FIELDS, get_old_role_name
from waldur_core.structure.registry import get_resource_type, get_service_type

User = auth.get_user_model()
logger = logging.getLogger(__name__)


def get_options_serializer_class(service_type):
    return next(
        cls
        for cls in ServiceOptionsSerializer.get_subclasses()
        if get_service_type(cls) == service_type
    )


@lru_cache
def get_resource_serializer_class(resource_type):
    try:
        return next(
            cls
            for cls in BaseResourceSerializer.get_subclasses()
            if get_resource_type(cls.Meta.model) == resource_type
            and get_service_type(cls) is not None
        )
    except StopIteration:
        return None


class PermissionFieldFilteringMixin:
    """
    Mixin allowing to filter related fields.

    In order to constrain the list of entities that can be used
    as a value for the field:

    1. Make sure that the entity in question has corresponding
       Permission class defined.

    2. Implement `get_filtered_field_names()` method
       in the class that this mixin is mixed into and return
       the field in question from that method.
    """

    def get_fields(self):
        fields = super().get_fields()

        try:
            request = self.context["request"]
            user = request.user
        except (KeyError, AttributeError):
            return fields

        for field_name in self.get_filtered_field_names():
            if field_name not in fields:  # field could be not required by user
                continue
            field = fields[field_name]
            field.queryset = filter_queryset_for_user(field.queryset, user)

        return fields

    def get_filtered_field_names(self):
        raise NotImplementedError(
            "Implement get_filtered_field_names() " "to return list of filtered fields"
        )


class FieldFilteringMixin:
    """
    Mixin allowing to filter fields by user.

    In order to constrain the list of fields implement
    `get_filtered_field()` method returning list of tuples
    (field name, func for check access).
    """

    def get_fields(self):
        fields = super().get_fields()

        try:
            request = self.context["request"]
            user = request.user
        except (KeyError, AttributeError):
            return fields

        for field_name, check_access in self.get_filtered_field():
            if field_name not in fields:
                continue

            if not check_access(user):
                del fields[field_name]

        return fields

    def get_filtered_field(self):
        raise NotImplementedError(
            "Implement get_filtered_field() " "to return list of tuples "
        )


class PermissionListSerializer(serializers.ListSerializer):
    """
    Allows to filter related queryset by user.
    Counterpart of PermissionFieldFilteringMixin.

    In order to use it set Meta.list_serializer_class. Example:

    >>> class PermissionProjectSerializer(BasicProjectSerializer):
    >>>     class Meta(BasicProjectSerializer.Meta):
    >>>         list_serializer_class = PermissionListSerializer
    >>>
    >>> class CustomerSerializer(serializers.HyperlinkedModelSerializer):
    >>>     projects = PermissionProjectSerializer(many=True, read_only=True)
    """

    def to_representation(self, data):
        try:
            request = self.context["request"]
            user = request.user
        except (KeyError, AttributeError):
            pass
        else:
            if isinstance(data, django_models.Manager | django_models.query.QuerySet):
                data = filter_queryset_for_user(data.all(), user)

        return super().to_representation(data)


class BasicUserSerializer(
    ProtectedMediaSerializerMixin, serializers.HyperlinkedModelSerializer
):
    class Meta:
        model = User
        fields = (
            "url",
            "uuid",
            "username",
            "full_name",
            "native_name",
            "email",
            "image",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }


class BasicProjectSerializer(core_serializers.BasicInfoSerializer):
    class Meta(core_serializers.BasicInfoSerializer.Meta):
        model = models.Project


class PermissionProjectSerializer(BasicProjectSerializer):
    resource_count = serializers.SerializerMethodField()

    class Meta(BasicProjectSerializer.Meta):
        list_serializer_class = PermissionListSerializer
        fields = BasicProjectSerializer.Meta.fields + (
            "image",
            "resource_count",
            "end_date",
        )

    def get_resource_count(self, project):
        from waldur_mastermind.marketplace import models as marketplace_models

        return (
            marketplace_models.Resource.objects.filter(
                project=project,
            )
            .exclude(state=marketplace_models.Resource.States.TERMINATED)
            .count()
        )


class ProjectTypeSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.ProjectType
        fields = ("uuid", "url", "name", "description")
        extra_kwargs = {
            "url": {"lookup_field": "uuid", "view_name": "project_type-detail"},
        }


class ProjectDetailsSerializerMixin(serializers.Serializer):
    def validate_description(self, value):
        return clean_html(value.strip())

    def validate_end_date(self, end_date):
        if end_date and end_date < timezone.datetime.today().date():
            raise serializers.ValidationError(
                {"end_date": _("Cannot be earlier than the current date.")}
            )
        return end_date


class ProjectSerializer(
    ProjectDetailsSerializerMixin,
    core_serializers.RestrictedSerializerMixin,
    PermissionFieldFilteringMixin,
    ProtectedMediaSerializerMixin,
    core_serializers.AugmentedSerializerMixin,
    serializers.HyperlinkedModelSerializer,
):
    resources_count = serializers.SerializerMethodField()
    oecd_fos_2007_label = serializers.ReadOnlyField(
        source="get_oecd_fos_2007_code_display"
    )

    class Meta:
        model = models.Project
        fields = (
            "url",
            "uuid",
            "name",
            "customer",
            "customer_uuid",
            "customer_name",
            "customer_native_name",
            "customer_abbreviation",
            "description",
            "created",
            "type",
            "type_name",
            "type_uuid",
            "backend_id",
            "end_date",
            "end_date_requested_by",
            "oecd_fos_2007_code",
            "oecd_fos_2007_label",
            "is_industry",
            "image",
            "resources_count",
        )
        protected_fields = ("end_date_requested_by",)
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "customer": {"lookup_field": "uuid"},
            "type": {"lookup_field": "uuid", "view_name": "project_type-detail"},
            "end_date_requested_by": {
                "lookup_field": "uuid",
                "view_name": "user-detail",
            },
        }
        related_paths = {
            "customer": ("uuid", "name", "native_name", "abbreviation"),
            "type": ("name", "uuid"),
        }

    @staticmethod
    def eager_load(queryset, request=None):
        related_fields = (
            "uuid",
            "name",
            "created",
            "description",
            "customer__uuid",
            "customer__name",
            "customer__native_name",
            "customer__abbreviation",
        )
        return queryset.select_related("customer").only(*related_fields)

    def get_filtered_field_names(self):
        return ("customer",)

    def validate(self, attrs):
        customer = (
            attrs.get("customer") if not self.instance else self.instance.customer
        )
        end_date = attrs.get("end_date")

        if end_date:
            if not has_permission(
                self.context["request"], PermissionEnum.DELETE_PROJECT, customer
            ):
                raise exceptions.PermissionDenied()
            attrs["end_date_requested_by"] = self.context["request"].user

        if settings.WALDUR_CORE.get("OECD_FOS_2007_CODE_MANDATORY"):
            if (not self.instance and not attrs.get("oecd_fos_2007_code")) or (
                self.instance
                and not self.instance.oecd_fos_2007_code
                and not attrs.get("oecd_fos_2007_code")
            ):
                raise serializers.ValidationError(
                    {"oecd_fos_2007_code": _("This field is required.")}
                )

        return attrs

    def get_resources_count(self, project):
        from waldur_mastermind.marketplace import models as marketplace_models

        return marketplace_models.Resource.objects.filter(
            state__in=(
                marketplace_models.Resource.States.OK,
                marketplace_models.Resource.States.UPDATING,
            ),
            project=project,
        ).count()


class CountrySerializerMixin(serializers.Serializer):
    COUNTRIES = core_fields.COUNTRIES
    if settings.WALDUR_CORE.get("COUNTRIES"):
        COUNTRIES = [
            item for item in COUNTRIES if item[0] in settings.WALDUR_CORE["COUNTRIES"]
        ]
    country = serializers.ChoiceField(
        required=False, choices=COUNTRIES, allow_blank=True
    )
    country_name = serializers.ReadOnlyField(source="get_country_display")


class CustomerSerializer(
    ProtectedMediaSerializerMixin,
    CountrySerializerMixin,
    core_serializers.RestrictedSerializerMixin,
    core_serializers.AugmentedSerializerMixin,
    serializers.HyperlinkedModelSerializer,
):
    projects = serializers.SerializerMethodField()
    display_name = serializers.ReadOnlyField(source="get_display_name")
    organization_group_name = serializers.ReadOnlyField(
        source="organization_group.name"
    )
    organization_group_uuid = serializers.ReadOnlyField(
        source="organization_group.uuid"
    )
    organization_group_parent_name = serializers.ReadOnlyField(
        source="organization_group.parent.name"
    )
    organization_group_parent_uuid = serializers.ReadOnlyField(
        source="organization_group.parent.uuid"
    )
    organization_group_type_name = serializers.ReadOnlyField(
        source="organization_group.type.name"
    )
    organization_group_type_uuid = serializers.ReadOnlyField(
        source="organization_group.type.uuid"
    )
    projects_count = serializers.SerializerMethodField()
    users_count = serializers.SerializerMethodField()

    class Meta:
        model = models.Customer
        fields = (
            "url",
            "uuid",
            "created",
            "organization_group",
            "organization_group_name",
            "organization_group_uuid",
            "organization_group_parent_name",
            "organization_group_parent_uuid",
            "organization_group_type_name",
            "organization_group_type_uuid",
            "display_name",
            "projects",
            "backend_id",
            "image",
            "blocked",
            "archived",
            "default_tax_percent",
            "accounting_start_date",
            "projects_count",
            "users_count",
            "sponsor_number",
            "country_name",
        ) + CUSTOMER_DETAILS_FIELDS
        staff_only_fields = (
            "access_subnets",
            "accounting_start_date",
            "default_tax_percent",
            "agreement_number",
            "domain",
            "organization_group",
            "blocked",
            "archived",
            "sponsor_number",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "organization_group": {
                "lookup_field": "uuid",
                "view_name": "organization-group-detail",
            },
        }

    def get_fields(self):
        fields = super().get_fields()

        try:
            request = self.context["view"].request
            user = request.user
        except (KeyError, AttributeError):
            return fields

        if not user.is_staff:
            for field_name in set(CustomerSerializer.Meta.staff_only_fields) & set(
                fields.keys()
            ):
                fields[field_name].read_only = True

        return fields

    def create(self, validated_data):
        user = self.context["request"].user
        if "domain" not in validated_data:
            # Staff can specify domain name on organization creation
            validated_data["domain"] = user.organization
        return super().create(validated_data)

    @staticmethod
    def eager_load(queryset, request=None):
        return queryset.prefetch_related("projects")

    def validate(self, attrs):
        country = attrs.get("country")
        vat_code = attrs.get("vat_code")

        if vat_code:
            # Check VAT format
            if not pyvat.is_vat_number_format_valid(vat_code, country):
                raise serializers.ValidationError(
                    {"vat_code": _("VAT number has invalid format.")}
                )

            # Check VAT number in EU VAT Information Exchange System
            # if customer is new or either VAT number or country of the customer has changed
            if (
                not self.instance
                or self.instance.vat_code != vat_code
                or self.instance.country != country
            ):
                check_result = pyvat.check_vat_number(vat_code, country)
                if check_result.is_valid:
                    attrs["vat_name"] = check_result.business_name
                    attrs["vat_address"] = check_result.business_address
                    if not attrs.get("contact_details"):
                        attrs["contact_details"] = attrs["vat_address"]
                elif check_result.is_valid is False:
                    raise serializers.ValidationError(
                        {"vat_code": _("VAT number is invalid.")}
                    )
                else:
                    logger.debug(
                        "Unable to check VAT number %s for country %s. Error message: %s",
                        vat_code,
                        country,
                        check_result.log_lines,
                    )
                    raise serializers.ValidationError(
                        {"vat_code": _("Unable to check VAT number.")}
                    )
        return attrs

    def get_projects_count(self, customer):
        return models.Project.available_objects.filter(customer=customer).count()

    def get_projects(self, customer):
        projects = models.Project.available_objects.filter(customer=customer)
        show_all_projects = self.context["request"].query_params.get(
            "show_all_projects"
        )
        if show_all_projects not in ["true", "True"]:
            query = self.context["request"].query_params.get("query")

            if query:
                projects = projects.filter(name__icontains=query)

        return PermissionProjectSerializer(
            projects, many=True, context=self.context
        ).data

    def get_users_count(self, customer):
        return count_customer_users(customer)


class AccessSubnetSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.AccessSubnet
        fields = (
            "uuid",
            "inet",
            "description",
            "customer",
        )
        extra_kwargs = {
            "customer": {"lookup_field": "uuid"},
        }

    def validate(self, validated_data):
        if not self.instance:
            customer = validated_data["customer"]
            permission = PermissionEnum.CREATE_ACCESS_SUBNET

            if not has_permission(self.context["request"], permission, customer):
                raise exceptions.PermissionDenied()

        return validated_data


class NestedCustomerSerializer(
    core_serializers.AugmentedSerializerMixin,
    core_serializers.HyperlinkedRelatedModelSerializer,
):
    class Meta:
        model = models.Customer
        fields = ("uuid", "url")
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }


class BasicCustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Customer
        fields = (
            "uuid",
            "name",
        )


class NestedProjectSerializer(
    core_serializers.AugmentedSerializerMixin,
    core_serializers.HyperlinkedRelatedModelSerializer,
):
    class Meta:
        model = models.Project
        fields = ("uuid", "url")
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }


class NestedProjectPermissionSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedRelatedField(
        source="scope", lookup_field="uuid", view_name="project-detail", read_only=True
    )
    uuid = serializers.ReadOnlyField(source="scope.uuid")
    name = serializers.ReadOnlyField(source="scope.name")
    role = serializers.SerializerMethodField()
    role_name = serializers.SerializerMethodField()

    class Meta:
        model = UserRole
        fields = [
            "url",
            "uuid",
            "name",
            "role",
            "role_name",
            "expiration_time",
        ]

    def get_role(self, instance):
        return get_old_role_name(instance.role.name)

    def get_role_name(self, instance):
        return instance.role.name


class CustomerUserSerializer(
    ProtectedMediaSerializerMixin,
    serializers.ModelSerializer,
):
    role = serializers.ReadOnlyField()
    expiration_time = serializers.ReadOnlyField(source="perm.expiration_time")
    projects = NestedProjectPermissionSerializer(many=True, read_only=True)
    role_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "url",
            "uuid",
            "username",
            "full_name",
            "email",
            "role",
            "role_name",
            "projects",
            "expiration_time",
            "image",
        ]
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }

    def get_role_name(self, user):
        customer = self.context["customer"]
        permission = UserRole.objects.filter(
            scope=customer,
            user=user,
            is_active=True,
        ).first()
        return permission and permission.role.name

    def to_representation(self, user):
        customer = self.context["customer"]
        permission = UserRole.objects.filter(
            content_type=ContentType.objects.get_for_model(models.Customer),
            object_id=customer.id,
            user=user,
            is_active=True,
            role__name__in=SYSTEM_CUSTOMER_ROLES,
        ).first()
        project_ids = customer.projects.values_list("id", flat=True)
        projects = UserRole.objects.filter(
            content_type=ContentType.objects.get_for_model(models.Project),
            object_id__in=project_ids,
            user=user,
            is_active=True,
        )
        setattr(user, "perm", permission)
        setattr(user, "role", permission and get_old_role_name(permission.role.name))
        setattr(user, "projects", projects)
        return super().to_representation(user)


class ProjectUserSerializer(serializers.ModelSerializer):
    role = serializers.ReadOnlyField()
    expiration_time = serializers.ReadOnlyField(source="perm.expiration_time")

    class Meta:
        model = User
        fields = [
            "url",
            "uuid",
            "username",
            "full_name",
            "email",
            "role",
            "expiration_time",
        ]
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }

    def to_representation(self, user):
        project = self.context["project"]
        permission = get_permissions(project, user).first()
        setattr(user, "perm", permission)
        setattr(user, "role", permission and get_old_role_name(permission.role.name))
        return super().to_representation(user)


class BasePermissionSerializer(
    core_serializers.AugmentedSerializerMixin, serializers.HyperlinkedModelSerializer
):
    role = serializers.SerializerMethodField()

    class Meta:
        fields = (
            "role",
            "user",
            "user_full_name",
            "user_native_name",
            "user_username",
            "user_uuid",
            "user_email",
        )
        related_paths = {
            "user": ("username", "full_name", "native_name", "uuid", "email"),
        }

    def get_role(self, instance):
        return get_old_role_name(instance.role.name)


class CustomerPermissionReviewSerializer(
    core_serializers.AugmentedSerializerMixin, serializers.HyperlinkedModelSerializer
):
    class Meta:
        model = models.CustomerPermissionReview
        view_name = "customer_permission_review-detail"
        fields = (
            "url",
            "uuid",
            "reviewer_full_name",
            "reviewer_uuid",
            "customer_uuid",
            "customer_name",
            "is_pending",
            "created",
            "closed",
        )
        read_only_fields = (
            "is_pending",
            "closed",
        )
        related_paths = {
            "reviewer": ("full_name", "uuid"),
            "customer": ("name", "uuid"),
        }
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }


class ProjectPermissionLogSerializer(BasePermissionSerializer):
    customer_uuid = serializers.ReadOnlyField(source="scope.customer.uuid")
    customer_name = serializers.ReadOnlyField(source="scope.customer.name")
    project_uuid = serializers.ReadOnlyField(source="scope.uuid")
    project_name = serializers.ReadOnlyField(source="scope.name")
    project_created = serializers.ReadOnlyField(source="scope.created")
    project_end_date = serializers.ReadOnlyField(source="scope.end_date")
    role = serializers.SerializerMethodField()
    project = serializers.HyperlinkedRelatedField(
        source="scope",
        view_name="project-detail",
        read_only=True,
        lookup_field="uuid",
    )

    class Meta(BasePermissionSerializer.Meta):
        model = UserRole
        fields = (
            "role",
            "created",
            "expiration_time",
            "created_by",
            "created_by_full_name",
            "created_by_username",
            "project",
            "project_uuid",
            "project_name",
            "project_created",
            "project_end_date",
            "customer_uuid",
            "customer_name",
        ) + BasePermissionSerializer.Meta.fields
        related_paths = dict(
            created_by=("full_name", "username"),
            **BasePermissionSerializer.Meta.related_paths,
        )
        view_name = "project_permission_log-detail"
        extra_kwargs = {
            "user": {
                "view_name": "user-detail",
                "lookup_field": "uuid",
                "queryset": User.objects.all(),
            },
            "created_by": {
                "view_name": "user-detail",
                "lookup_field": "uuid",
                "read_only": True,
            },
        }


class UserSerializer(
    core_serializers.RestrictedSerializerMixin,
    core_serializers.AugmentedSerializerMixin,
    ProtectedMediaSerializerMixin,
    serializers.HyperlinkedModelSerializer,
):
    email = serializers.EmailField()
    agree_with_policy = serializers.BooleanField(
        write_only=True,
        required=False,
        help_text=_("User must agree with the policy to register."),
    )
    competence = serializers.ChoiceField(
        choices=settings.WALDUR_CORE.get("USER_COMPETENCE_LIST", []),
        allow_blank=True,
        required=False,
    )
    token = serializers.ReadOnlyField(source="auth_token.key")
    permissions = serializers.SerializerMethodField()
    requested_email = serializers.SerializerMethodField()
    full_name = serializers.CharField(max_length=200, required=False)
    identity_provider_name = serializers.SerializerMethodField()
    identity_provider_label = serializers.SerializerMethodField()
    identity_provider_management_url = serializers.SerializerMethodField()
    identity_provider_fields = serializers.SerializerMethodField()

    def get_permissions(self, user):
        perms = UserRole.objects.filter(user=user, is_active=True)
        serializer = PermissionSerializer(instance=perms, many=True)
        return serializer.data

    def get_requested_email(self, user):
        try:
            requested_email = core_models.ChangeEmailRequest.objects.get(user=user)
            return requested_email.email
        except core_models.ChangeEmailRequest.DoesNotExist:
            pass

    def get_identity_provider_name(self, user):
        return utils.get_identity_provider_name(user.registration_method)

    def get_identity_provider_label(self, user):
        return utils.get_identity_provider_label(user.registration_method)

    def get_identity_provider_management_url(self, user):
        return utils.get_identity_provider_management_url(user.registration_method)

    def get_identity_provider_fields(self, user):
        return utils.get_identity_provider_fields(user.registration_method)

    class Meta:
        model = User
        fields = (
            "url",
            "uuid",
            "username",
            "full_name",
            "native_name",
            "job_title",
            "email",
            "phone_number",
            "organization",
            "civil_number",
            "description",
            "is_staff",
            "is_active",
            "is_support",
            "token",
            "token_lifetime",
            "registration_method",
            "date_joined",
            "agree_with_policy",
            "agreement_date",
            "preferred_language",
            "competence",
            "permissions",
            "requested_email",
            "affiliations",
            "first_name",
            "last_name",
            "identity_provider_name",
            "identity_provider_label",
            "identity_provider_management_url",
            "identity_provider_fields",
            "image",
        )
        read_only_fields = (
            "uuid",
            "civil_number",
            "registration_method",
            "date_joined",
            "agreement_date",
            "affiliations",
        )
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }
        protected_fields = ("email",)

    def get_fields(self):
        fields = super().get_fields()

        try:
            request = self.context["view"].request
            user = request.user
        except (KeyError, AttributeError):
            return fields

        if user.is_anonymous:
            return fields

        if not user.is_staff:
            protected_fields = ("is_active", "is_staff", "is_support", "description")
            if user.is_support:
                for field in protected_fields:
                    if field in fields:
                        fields[field].read_only = True
            else:
                for field in protected_fields:
                    if field in fields:
                        del fields[field]

        if not self._can_see_token(user):
            if "token" in fields:
                del fields["token"]
            if "token_lifetime" in fields:
                del fields["token_lifetime"]

        if request.method in ("PUT", "PATCH"):
            fields["username"].read_only = True
            protected_methods = settings.WALDUR_CORE[
                "PROTECT_USER_DETAILS_FOR_REGISTRATION_METHODS"
            ]
            if (
                user.registration_method
                and user.registration_method in protected_methods
            ):
                detail_fields = (
                    "full_name",
                    "native_name",
                    "job_title",
                    "email",
                    "phone_number",
                    "organization",
                )
                for field in detail_fields:
                    fields[field].read_only = True

        return fields

    def _can_see_token(self, user):
        # Nobody apart from the user herself can see her token.
        # User can see the token either via details view or /api/users/me

        if isinstance(self.instance, list) and len(self.instance) == 1:
            return self.instance[0] == user
        else:
            return self.instance == user

    def validate(self, attrs):
        agree_with_policy = attrs.pop("agree_with_policy", False)
        if self.instance and not self.instance.agreement_date:
            if not agree_with_policy:
                if (
                    self.instance.is_active
                    and "is_active" in attrs.keys()
                    and not attrs["is_active"]
                    and len(attrs) == 1
                ):
                    # Deactivation of user.
                    pass
                else:
                    raise serializers.ValidationError(
                        {"agree_with_policy": _("User must agree with the policy.")}
                    )
            else:
                attrs["agreement_date"] = timezone.now()

        if self.instance:
            idp_fields = self.get_identity_provider_fields(self.instance)
            allowed_fields = set(attrs.keys()) - set(idp_fields)
            attrs = {k: v for k, v in attrs.items() if k in allowed_fields}

        if "full_name" in attrs and "first_name" in attrs:
            raise serializers.ValidationError(
                {"first_name": _("Cannot specify first name with full name")}
            )
        elif "full_name" in attrs and "last_name" in attrs:
            raise serializers.ValidationError(
                {"last_name": _("Cannot specify last name with full name")}
            )

        # Convert validation error from Django to DRF
        # https://github.com/tomchristie/django-rest-framework/issues/2145
        try:
            user = User(id=getattr(self.instance, "id", None), **attrs)
            user.clean()

        except django_exceptions.ValidationError as error:
            raise exceptions.ValidationError(error.message_dict)
        return attrs


class UserEmailChangeSerializer(serializers.Serializer):
    email = serializers.EmailField()


class SshKeySerializer(serializers.HyperlinkedModelSerializer):
    user_uuid = serializers.ReadOnlyField(source="user.uuid")

    class Meta:
        model = core_models.SshPublicKey
        fields = (
            "url",
            "uuid",
            "name",
            "public_key",
            "fingerprint",
            "user_uuid",
            "is_shared",
            "type",
        )
        read_only_fields = ("fingerprint", "is_shared")
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }

    def validate_name(self, value):
        return value.strip()

    def validate_public_key(self, value):
        value = value.strip()
        if len(value.splitlines()) > 1:
            raise serializers.ValidationError(
                _("Key is not valid: it should be single line.")
            )

        try:
            core_models.get_ssh_key_fingerprint(value)
        except (IndexError, TypeError):
            raise serializers.ValidationError(
                _("Key is not valid: cannot generate fingerprint from it.")
            )
        return value


class MoveProjectSerializer(serializers.Serializer):
    customer = NestedCustomerSerializer(
        queryset=models.Customer.objects.all(), required=True, many=False
    )


class ServiceOptionsSerializer(serializers.Serializer):
    class Meta:
        secret_fields = ()

    @classmethod
    def get_subclasses(cls):
        for subclass in cls.__subclasses__():
            yield from subclass.get_subclasses()
            yield subclass


class ServiceSettingsSerializer(
    PermissionFieldFilteringMixin,
    core_serializers.RestrictedSerializerMixin,
    core_serializers.AugmentedSerializerMixin,
    serializers.HyperlinkedModelSerializer,
):
    customer_native_name = serializers.ReadOnlyField(source="customer.native_name")
    state = MappedChoiceField(
        choices=[(v, k) for k, v in core_models.StateMixin.States.CHOICES],
        choice_mappings={v: k for k, v in core_models.StateMixin.States.CHOICES},
        read_only=True,
    )
    scope = core_serializers.GenericRelatedField(
        related_models=models.BaseResource.get_all_models(),
        required=False,
        allow_null=True,
    )
    options = serializers.DictField()

    class Meta:
        model = models.ServiceSettings
        fields = (
            "url",
            "uuid",
            "name",
            "type",
            "state",
            "error_message",
            "shared",
            "customer",
            "customer_name",
            "customer_native_name",
            "terms_of_services",
            "scope",
            "options",
        )
        read_only_fields = ("state", "error_message")
        related_paths = ("customer",)
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
            "customer": {"lookup_field": "uuid"},
        }

    def get_filtered_field_names(self):
        return ("customer",)

    @staticmethod
    def eager_load(queryset, request=None):
        return queryset.select_related("customer")

    def get_fields(self):
        fields = super().get_fields()
        method = self.context["view"].request.method
        if method == "GET" and "options" in fields:
            fields["options"] = serializers.SerializerMethodField("get_options")
        return fields

    def get_options(self, service):
        options = {
            "backend_url": service.backend_url,
            "username": service.username,
            "password": service.password,
            "domain": service.domain,
            "token": service.token,
            **service.options,
        }
        request = self.context["request"]

        if request.user.is_staff:
            return options

        if service.customer and service.customer.has_user(
            request.user, models.CustomerRole.OWNER
        ):
            return options

        options_serializer_class = get_options_serializer_class(service.type)
        secret_fields = options_serializer_class.Meta.secret_fields
        return {k: v for (k, v) in options.items() if k not in secret_fields}


class BasicResourceSerializer(serializers.Serializer):
    uuid = serializers.ReadOnlyField()
    name = serializers.ReadOnlyField()
    resource_type = serializers.SerializerMethodField()

    def get_resource_type(self, resource):
        return get_resource_type(resource)


class ManagedResourceSerializer(BasicResourceSerializer):
    project_name = serializers.ReadOnlyField(source="project.name")
    project_uuid = serializers.ReadOnlyField(source="project.uuid")

    customer_uuid = serializers.ReadOnlyField(source="project.customer.uuid")
    customer_name = serializers.ReadOnlyField(source="project.customer.name")


class BaseResourceSerializer(
    core_serializers.RestrictedSerializerMixin,
    PermissionFieldFilteringMixin,
    core_serializers.AugmentedSerializerMixin,
    serializers.HyperlinkedModelSerializer,
):
    state = serializers.ReadOnlyField(source="get_state_display")

    project = serializers.HyperlinkedRelatedField(
        queryset=models.Project.objects.all(),
        view_name="project-detail",
        lookup_field="uuid",
    )

    project_name = serializers.ReadOnlyField(source="project.name")
    project_uuid = serializers.ReadOnlyField(source="project.uuid")

    service_name = serializers.ReadOnlyField(source="service_settings.name")

    service_settings = serializers.HyperlinkedRelatedField(
        queryset=models.ServiceSettings.objects.all(),
        view_name="servicesettings-detail",
        lookup_field="uuid",
    )
    service_settings_uuid = serializers.ReadOnlyField(source="service_settings.uuid")
    service_settings_state = serializers.ReadOnlyField(
        source="service_settings.get_state_display"
    )
    service_settings_error_message = serializers.ReadOnlyField(
        source="service_settings.error_message"
    )

    customer = serializers.HyperlinkedRelatedField(
        source="project.customer",
        view_name="customer-detail",
        read_only=True,
        lookup_field="uuid",
    )

    customer_name = serializers.ReadOnlyField(source="project.customer.name")
    customer_abbreviation = serializers.ReadOnlyField(
        source="project.customer.abbreviation"
    )
    customer_native_name = serializers.ReadOnlyField(
        source="project.customer.native_name"
    )

    created = serializers.DateTimeField(read_only=True)
    resource_type = serializers.SerializerMethodField()

    access_url = serializers.SerializerMethodField()

    class Meta:
        model = NotImplemented
        fields = (
            "url",
            "uuid",
            "name",
            "description",
            "service_name",
            "service_settings",
            "service_settings_uuid",
            "service_settings_state",
            "service_settings_error_message",
            "project",
            "project_name",
            "project_uuid",
            "customer",
            "customer_name",
            "customer_native_name",
            "customer_abbreviation",
            "error_message",
            "error_traceback",
            "resource_type",
            "state",
            "created",
            "modified",
            "backend_id",
            "access_url",
        )
        protected_fields = (
            "project",
            "service_settings",
        )
        read_only_fields = ("error_message", "error_traceback", "backend_id")
        extra_kwargs = {
            "url": {"lookup_field": "uuid"},
        }

    def get_filtered_field_names(self):
        return ("project", "service_settings")

    def get_resource_type(self, obj):
        return get_resource_type(obj)

    def get_resource_fields(self):
        return [f.name for f in self.Meta.model._meta.get_fields()]

    # an optional generic URL for accessing a resource
    def get_access_url(self, obj):
        return obj.get_access_url()

    def get_fields(self):
        fields = super().get_fields()
        # skip validation on object update
        if not self.instance:
            service_type = get_service_type(self.Meta.model)
            if (
                "service_settings" in fields
                and not fields["service_settings"].read_only
            ):
                queryset = fields["service_settings"].queryset.filter(type=service_type)
                fields["service_settings"].queryset = queryset
        return fields

    @transaction.atomic
    def create(self, validated_data):
        data = validated_data.copy()
        fields = self.get_resource_fields()

        # Remove `virtual` properties which ain't actually belong to the model
        data = {key: value for key, value in data.items() if key in fields}

        resource = super().create(data)
        resource.increase_backend_quotas_usage(validate=True)
        return resource

    @classmethod
    def get_subclasses(cls):
        for subclass in cls.__subclasses__():
            yield from subclass.get_subclasses()
            if subclass.Meta.model != NotImplemented:
                yield subclass


class BaseResourceActionSerializer(BaseResourceSerializer):
    project = serializers.HyperlinkedRelatedField(
        view_name="project-detail",
        lookup_field="uuid",
        read_only=True,
    )
    service_settings = serializers.HyperlinkedRelatedField(
        view_name="servicesettings-detail",
        lookup_field="uuid",
        read_only=True,
    )

    class Meta(BaseResourceSerializer.Meta):
        pass


class SshPublicKeySerializerMixin(serializers.HyperlinkedModelSerializer):
    ssh_public_key = serializers.HyperlinkedRelatedField(
        view_name="sshpublickey-detail",
        lookup_field="uuid",
        queryset=core_models.SshPublicKey.objects.all(),
        required=False,
        write_only=True,
    )

    def get_fields(self):
        fields = super().get_fields()
        if "request" in self.context:
            user = self.context["request"].user
            ssh_public_key = fields.get("ssh_public_key")
            if ssh_public_key:
                if not user.is_staff:
                    visible_users = list(filter_visible_users(User.objects.all(), user))
                    subquery = Q(user__in=visible_users) | Q(is_shared=True)
                    ssh_public_key.queryset = ssh_public_key.queryset.filter(subquery)
        return fields


class VirtualMachineSerializer(SshPublicKeySerializerMixin, BaseResourceSerializer):
    external_ips = serializers.ListField(
        child=serializers.IPAddressField(protocol="ipv4"),
        read_only=True,
    )
    internal_ips = serializers.ListField(
        child=serializers.IPAddressField(protocol="ipv4"),
        read_only=True,
    )

    class Meta(BaseResourceSerializer.Meta):
        fields = BaseResourceSerializer.Meta.fields + (
            "start_time",
            "cores",
            "ram",
            "disk",
            "min_ram",
            "min_disk",
            "ssh_public_key",
            "user_data",
            "external_ips",
            "internal_ips",
            "latitude",
            "longitude",
            "key_name",
            "key_fingerprint",
            "image_name",
        )
        read_only_fields = BaseResourceSerializer.Meta.read_only_fields + (
            "start_time",
            "cores",
            "ram",
            "disk",
            "min_ram",
            "min_disk",
            "external_ips",
            "internal_ips",
            "latitude",
            "longitude",
            "key_name",
            "key_fingerprint",
            "image_name",
        )
        protected_fields = BaseResourceSerializer.Meta.protected_fields + (
            "user_data",
            "ssh_public_key",
        )

    def create(self, validated_data):
        if "image" in validated_data:
            validated_data["image_name"] = validated_data["image"].name
        return super().create(validated_data)


class BasePropertySerializer(
    core_serializers.AugmentedSerializerMixin,
    serializers.HyperlinkedModelSerializer,
):
    class Meta:
        model = NotImplemented


class OrganizationGroupSerializer(serializers.HyperlinkedModelSerializer):
    type = serializers.UUIDField(source="type.uuid")
    type_name = serializers.CharField(source="type.name", read_only=True)
    parent_uuid = serializers.ReadOnlyField(source="parent.uuid")
    parent_name = serializers.ReadOnlyField(source="parent.type.name")
    customers_count = serializers.ReadOnlyField()

    class Meta:
        model = models.OrganizationGroup
        fields = (
            "uuid",
            "url",
            "name",
            "type",
            "type_name",
            "parent_uuid",
            "parent_name",
            "parent",
            "customers_count",
        )
        extra_kwargs = {
            "url": {"view_name": "organization-group-detail", "lookup_field": "uuid"},
            "parent": {
                "lookup_field": "uuid",
                "view_name": "organization-group-detail",
            },
        }

    def create(self, validated_data):
        type_uuid = validated_data.pop("type", None)
        if type_uuid:
            validated_data["type"] = models.OrganizationGroupType.objects.get(
                uuid=type_uuid["uuid"]
            )
        return super().create(validated_data)

    def update(self, instance, validated_data):
        type_uuid = validated_data.pop("type", None)
        if type_uuid:
            instance.type = models.OrganizationGroupType.objects.get(
                uuid=type_uuid["uuid"]
            )
        instance.name = validated_data.get("name", instance.name)
        instance.save()
        return instance


class OrganizationGroupTypesSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.OrganizationGroupType
        fields = (
            "uuid",
            "url",
            "name",
        )
        extra_kwargs = {
            "url": {
                "lookup_field": "uuid",
                "view_name": "organization-group-type-detail",
            },
        }


class UserAgreementSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = models.UserAgreement
        fields = ("url", "content", "agreement_type", "created", "modified")
        extra_kwargs = {
            "url": {"lookup_field": "uuid", "view_name": "user-agreements-detail"}
        }


class NotificationTemplateDetailSerializers(serializers.ModelSerializer):
    content = serializers.SerializerMethodField()
    original_content = serializers.SerializerMethodField()
    is_content_overridden = serializers.SerializerMethodField()

    class Meta:
        model = core_models.NotificationTemplate
        fields = (
            "uuid",
            "url",
            "path",
            "name",
            "content",
            "original_content",
            "is_content_overridden",
        )
        extra_kwargs = {
            "url": {
                "view_name": "notification-messages-templates-detail",
                "lookup_field": "uuid",
            },
        }

    def get_content(self, obj):
        return get_template(obj.path).template.source

    def get_original_content(self, obj):
        from django.template.engine import Engine
        from django.template.loaders.app_directories import Loader

        loader = Loader(Engine())
        for origin in loader.get_template_sources(obj.path):
            try:
                source = loader.get_contents(origin)
            except Exception:
                continue
            if source:
                return source

    def get_is_content_overridden(self, obj):
        return self.get_content(obj) != self.get_original_content(obj)


class NotificationSerializer(serializers.HyperlinkedModelSerializer):
    templates = NotificationTemplateDetailSerializers(many=True, read_only=True)

    class Meta:
        model = core_models.Notification
        fields = (
            "uuid",
            "url",
            "key",
            "description",
            "enabled",
            "created",
            "templates",
        )
        read_only_fields = ("created", "enabled")
        extra_kwargs = {
            "url": {
                "view_name": "notification-messages-detail",
                "lookup_field": "uuid",
            },
        }


class NotificationTemplateUpdateSerializers(serializers.Serializer):
    content = serializers.CharField()


class AuthTokenSerializers(serializers.HyperlinkedModelSerializer):
    user_first_name = serializers.CharField(source="user.first_name")
    user_last_name = serializers.CharField(source="user.last_name")
    user_username = serializers.CharField(source="user.username")
    user_is_active = serializers.CharField(source="user.is_active")
    user_token_lifetime = serializers.CharField(source="user.token_lifetime")

    class Meta:
        model = authtoken_models.Token
        fields = (
            "url",
            "created",
            "user",
            "user_first_name",
            "user_last_name",
            "user_username",
            "user_is_active",
            "user_token_lifetime",
        )
        extra_kwargs = {
            "url": {
                "view_name": "auth-tokens-detail",
                "lookup_field": "user_id",
            },
            "user": {"lookup_field": "uuid", "view_name": "user-detail"},
        }
