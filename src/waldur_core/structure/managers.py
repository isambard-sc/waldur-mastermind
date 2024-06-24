from django.contrib.contenttypes.models import ContentType
from django.db import models

from waldur_core.core import utils as core_utils
from waldur_core.core.managers import GenericKeyMixin
from waldur_core.permissions.models import Role
from waldur_core.permissions.utils import get_scope_ids, get_user_ids
from waldur_core.structure import models as structure_models


def build_filter(path, ids):
    if path == "self":
        path = "id"
    return models.Q(**{f"{path}__in": ids})


def filter_queryset_for_user(queryset, user):
    if user is None or user.is_staff or user.is_support:
        return queryset

    try:
        permissions = queryset.model.Permissions
    except AttributeError:
        return queryset

    subquery = models.Q()

    customer_path = getattr(permissions, "customer_path", None)
    project_path = getattr(permissions, "project_path", None)

    if customer_path:
        subquery |= build_filter(customer_path, get_connected_customers(user))

    if project_path:
        subquery |= build_filter(project_path, get_connected_projects(user))

    build_query = getattr(permissions, "build_query", None)
    if build_query:
        subquery |= build_query(user)

    if not subquery:
        return queryset

    return queryset.filter(subquery).distinct()


def filter_queryset_by_user_ip(queryset, request):
    user = request.user
    user_ip = core_utils.get_ip_address(request)

    if user is None or user.is_staff or user.is_support or not user_ip:
        return queryset

    try:
        permissions = queryset.model.Permissions
    except AttributeError:
        return queryset

    customer_path = getattr(permissions, "customer_path", None)
    if not customer_path:
        return queryset

    if customer_path == "self":
        path = "id__in"
        none_path = "id"
    else:
        path = customer_path + "__id__in"
        none_path = customer_path + "_id"

    customers_ids = structure_models.Customer.objects.filter(
        models.Q(access_subnet_set__inet__isnull=True)
        | models.Q(access_subnet_set__inet__net_contains_or_equals=user_ip)
    ).values_list("id", flat=True)
    subquery = models.Q(**{path: customers_ids}) | models.Q(**{none_path: None})
    return queryset.filter(subquery)


class StructureQueryset(models.QuerySet):
    """Provides additional filtering by customer or project (based on permission definition).

    Example:

        .. code-block:: python

            Instance.objects.filter(project=12)

            Droplet.objects.filter(
                customer__name__startswith='A',
                state=Droplet.States.ONLINE)

            Droplet.objects.filter(Q(customer__name='Alice') | Q(customer__name='Bob'))
    """

    def exclude(self, *args, **kwargs):
        return super().exclude(
            *[self._patch_query_argument(a) for a in args],
            **self._filter_by_custom_fields(**kwargs),
        )

    def filter(self, *args, **kwargs):
        return super().filter(
            *[self._patch_query_argument(a) for a in args],
            **self._filter_by_custom_fields(**kwargs),
        )

    def _patch_query_argument(self, arg):
        # patch Q() objects if passed and add support of custom fields
        if isinstance(arg, models.Q):
            children = []
            for opt in arg.children:
                if isinstance(opt, models.Q):
                    children.append(self._patch_query_argument(opt))
                else:
                    args = self._filter_by_custom_fields(**dict([opt]))
                    children.append(tuple(args.items())[0])
            arg.children = children
        return arg

    def _filter_by_custom_fields(self, **kwargs):
        # traverse over filter arguments in search of custom fields
        args = {}
        fields = [f.name for f in self.model._meta.get_fields()]
        for field, val in kwargs.items():
            base_field = field.split("__")[0]
            if base_field in fields:
                args.update(**{field: val})
            elif base_field in ("customer", "project"):
                args.update(self._filter_by_permission_fields(base_field, field, val))
            else:
                args.update(**{field: val})

        return args

    def _filter_by_permission_fields(self, name, field, value):
        # handle fields connected via permissions relations
        extra = "__".join(field.split("__")[1:]) if "__" in field else None
        try:
            # look for the target field path in Permissions class,
            path = getattr(self.model.Permissions, "%s_path" % name)
        except AttributeError:
            # fallback to FieldError if it's missed
            return {field: value}
        else:
            if path == "self":
                if extra:
                    return {extra: value}
                else:
                    return {
                        "pk": value.pk if isinstance(value, models.Model) else value
                    }
            else:
                if extra:
                    path += "__" + extra
                return {path: value}


StructureManager = models.Manager.from_queryset(StructureQueryset)


class ServiceSettingsManager(GenericKeyMixin, models.Manager):
    """Allows to filter and get service settings by generic key"""

    def get_available_models(self):
        """Return list of models that are acceptable"""
        from waldur_core.structure.models import BaseResource

        return BaseResource.get_all_models()


class SharedServiceSettingsManager(ServiceSettingsManager):
    def get_queryset(self):
        return super().get_queryset().filter(shared=True)


class PrivateServiceSettingsManager(ServiceSettingsManager):
    def get_queryset(self):
        return super().get_queryset().filter(shared=False)


def get_connected_customers(user, role=None):
    ctype = ContentType.objects.get_for_model(structure_models.Customer)
    return get_scope_ids(user, ctype, role)


def get_connected_projects(user, role=None):
    ctype = ContentType.objects.get_for_model(structure_models.Project)
    return get_scope_ids(user, ctype, role)


def get_connected_customers_by_permission(user, permission):
    ctype = ContentType.objects.get_for_model(structure_models.Customer)
    roles = list(
        Role.objects.filter(
            content_type=ctype, is_active=True, permissions__permission=permission
        ).values_list("name", flat=True)
    )
    if not roles:
        return structure_models.Customer.objects.none()
    return get_connected_customers(user, roles)


def get_connected_projects_by_permission(user, permission):
    ctype = ContentType.objects.get_for_model(structure_models.Project)
    roles = list(
        Role.objects.filter(
            content_type=ctype, is_active=True, permissions__permission=permission
        ).values_list("name", flat=True)
    )
    if not roles:
        return structure_models.Project.objects.none()
    return get_connected_projects(user, roles)


def get_customer_users(scope_ids, role=None):
    ctype = ContentType.objects.get_for_model(structure_models.Customer)
    return get_user_ids(ctype, scope_ids, role)


def get_project_users(scope_ids, role=None):
    ctype = ContentType.objects.get_for_model(structure_models.Project)
    return get_user_ids(ctype, scope_ids, role)


def get_visible_users(user):
    customer_users = get_customer_users(get_visible_customers(user))
    project_users = get_project_users(get_visible_projects(user))
    return customer_users.union(project_users)


def get_nested_customer_users(customer):
    customer_users = get_customer_users(customer.id)
    project_users = get_project_users(customer.projects.values_list("id", flat=True))
    return customer_users.union(project_users)


def count_customer_users(customer):
    return get_nested_customer_users(customer).count()


def get_visible_customers(user):
    direct_projects = get_connected_projects(user)
    direct_customers = get_connected_customers(user)
    indirect_customers = structure_models.Project.objects.filter(
        id__in=direct_projects
    ).values_list("customer_id", flat=True)
    return direct_customers.union(indirect_customers)


def get_visible_projects(user):
    direct_customers = get_connected_customers(user)
    direct_projects = get_connected_projects(user)
    indirect_projects = structure_models.Project.objects.filter(
        customer_id__in=direct_customers
    ).values_list("id", flat=True)
    return direct_projects.union(indirect_projects)


def get_organization_groups(user):
    return structure_models.Customer.objects.filter(
        id__in=get_visible_customers(user)
    ).values("organization_group")
