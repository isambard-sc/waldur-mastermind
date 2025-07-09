import logging

from django.utils.translation import gettext_lazy as _
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, response, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied

from waldur_core.core.enums import ReviewStates
from waldur_core.core import executors as core_executors
from waldur_core.structure import filters as structure_filters
from waldur_core.structure import models as structure_models
from waldur_core.structure import permissions as structure_permissions
from waldur_core.structure import views as structure_views
from waldur_core.core import views as core_views
from waldur_core.core import models as core_models
from waldur_core.core.serializers import ReviewCommentSerializer
from waldur_core.structure.filters import GenericRoleFilter
from waldur_core.core.validators import StateValidator

from waldur_core.permissions.fixtures import ServiceProviderRole
from waldur_core.core.permissions import IsAdminOrReadOnly
from waldur_core.structure.permissions import IsAdminOrOwner
from waldur_core.structure.permissions import _has_owner_access

from . import executors, filters, models, serializers

logger = logging.getLogger(__name__)


class AllocationViewSet(structure_views.ResourceViewSet):
    queryset = models.Allocation.objects.all().order_by("name")
    serializer_class = serializers.AllocationSerializer
    filterset_class = filters.AllocationFilter

    create_executor = executors.AllocationCreateExecutor
    update_executor = core_executors.EmptyExecutor
    pull_executor = executors.AllocationPullExecutor

    destroy_permissions = [structure_permissions.is_administrator]
    delete_executor = executors.AllocationDeleteExecutor

    set_limits_permissions = [structure_permissions.is_staff]
    set_limits_serializer_class = serializers.AllocationSetLimitsSerializer

    @action(detail=True, methods=["post"])
    def set_limits(self, request, uuid=None):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        executors.AllocationSetLimitsExecutor().execute(instance)
        return response.Response(
            {"status": _("Setting limits was scheduled.")},
            status=status.HTTP_202_ACCEPTED,
        )


class RemoteAllocationViewSet(structure_views.ResourceViewSet):
    queryset = models.RemoteAllocation.objects.all().order_by("name")
    serializer_class = serializers.RemoteAllocationSerializer
    filterset_class = filters.RemoteAllocationFilter

    create_executor = executors.RemoteAllocationCreateExecutor
    update_executor = core_executors.EmptyExecutor
    pull_executor = executors.RemoteAllocationPullExecutor

    destroy_permissions = [structure_permissions.is_administrator]
    delete_executor = executors.RemoteAllocationDeleteExecutor

    set_limits_permissions = [structure_permissions.is_staff]
    set_limits_serializer_class = serializers.RemoteAllocationSetLimitsSerializer

    @action(detail=True, methods=["post"])
    def set_limits(self, request, uuid=None):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        executors.RemoteAllocationSetLimitsExecutor().execute(instance)
        return response.Response(
            {"status": _("Setting limits was scheduled.")},
            status=status.HTTP_202_ACCEPTED,
        )


class AllocationUserUsageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = models.AllocationUserUsage.objects.all().order_by("year", "month")
    serializer_class = serializers.AllocationUserUsageSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)
    filterset_class = filters.AllocationUserUsageFilter


class RemoteAllocationUserUsageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = models.RemoteAllocationUserUsage.objects.all().order_by("year", "month")
    serializer_class = serializers.RemoteAllocationUserUsageSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)
    filterset_class = filters.RemoteAllocationUserUsageFilter


class AssociationViewSet(viewsets.ReadOnlyModelViewSet):
    lookup_field = "uuid"
    queryset = models.Association.objects.all().order_by("username")
    serializer_class = serializers.AssociationSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)
    filterset_class = filters.AssociationFilter


class RemoteAssociationViewSet(viewsets.ReadOnlyModelViewSet):
    lookup_field = "uuid"
    queryset = models.RemoteAssociation.objects.all()
    serializer_class = serializers.RemoteAssociationSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)
    filterset_class = filters.RemoteAssociationFilter


class UserInfoViewSet(core_views.ActionsViewSet):
    queryset = models.UserInfo.objects.all().order_by("shortname")
    lookup_field = "user"
    serializer_class = serializers.UserInfoSerializer
    permission_classes = (
        permissions.IsAuthenticated,
        IsAdminOrOwner,
        IsAdminOrReadOnly,
    )

    filterset_class = filters.UserInfoFilter

    def _get(self, user):
        user = core_models.User.objects.get(uuid=user)

        userinfo, created = models.UserInfo.objects.get_or_create(user=user)
        userinfo.sanitise()

        if created:
            logger.info(f"Created UserInfo {userinfo} for user {user}")
        else:
            logger.info(f"Retrieved UserInfo {userinfo} for user {user}")

        return userinfo

    def retrieve(self, request, pk=None, user=None):
        logger.info(f"Retrieving UserInfo {pk} : {request} : {user}")
        try:
            userinfo = self._get(user)
        except Exception as e:
            logger.error(f"Error retrieving user {user} : {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = serializers.UserInfoSerializer(
            instance=userinfo, context={"request": request}
        )

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"])
    def me(self, request):
        logger.info(f"Retrieving UserInfo for 'me'=user {request.user}")

        try:
            userinfo = self._get(request.user.uuid)
        except Exception as e:
            logger.error(f"Error retrieving user {request.user}: {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = serializers.UserInfoSerializer(
            instance=userinfo, context={"request": request}
        )

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["PUT"])
    def set_shortname(self, request, user=None):
        try:
            shortname = str(request.data["shortname"])
        except Exception as e:
            logger.error(f"You must provide the 'shortname' field: {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            userinfo = self._get(user)
        except Exception as e:
            logger.error(f"Error retrieving user {user}: {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)

        user = userinfo.user

        if request.user != user and not request.user.is_staff:
            logger.error(
                f"User {request.user} is not allowed to set shortname for user {user}"
            )
            return Response(status=status.HTTP_403_FORBIDDEN)

        try:
            userinfo.set_shortname(shortname)
            userinfo.save()
        except Exception as e:
            logger.error(f"Error setting shortname for user {user}: {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        serializer = serializers.UserInfoSerializer(
            instance=userinfo, context={"request": request}
        )

        return Response(serializer.data, status=status.HTTP_200_OK)


class ProjectClassViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = models.ProjectClass.objects.all().order_by("name")
    serializer_class = serializers.ProjectClassSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)
    filterset_class = filters.ProjectClassFilter


class ProjectInfoViewSet(core_views.ActionsViewSet):
    queryset = models.ProjectInfo.objects.all().order_by("shortname")
    lookup_field = "project"
    serializer_class = serializers.ProjectInfoSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filterset_class = filters.ProjectInfoFilter

    def _get(self, project):
        project = structure_models.Project.objects.get(uuid=project)

        projectinfo, created = models.ProjectInfo.objects.get_or_create(project=project)
        projectinfo.sanitise()

        if created:
            logger.info(f"Created ProjectInfo {projectinfo} for project {project}")
        else:
            logger.info(f"Retrieved ProjectInfo {projectinfo} for project {project}")

        return projectinfo

    def retrieve(self, request, pk=None, project=None):
        logger.info(f"Retrieving ProjectInfo {pk} : {request} : {project}")
        try:
            projectinfo = self._get(project)
        except Exception as e:
            logger.error(f"Error retrieving project {project} : {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = serializers.ProjectInfoSerializer(
            instance=projectinfo, context={"request": request}
        )

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["PUT"])
    def set_shortname(self, request, project=None):
        try:
            shortname = str(request.data["shortname"])
        except Exception as e:
            logger.error(f"You must provide the 'shortname' field: {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            projectinfo = self._get(project)
        except Exception as e:
            logger.error(f"Error retrieving project {project}: {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)

        project = projectinfo.project

        if not request.user.is_staff:
            logger.error(
                f"User {request.user} is not allowed to set shortname for project {project}"
            )
            return Response(status=status.HTTP_403_FORBIDDEN)

        try:
            projectinfo.set_shortname(shortname)
            projectinfo.save()
        except Exception as e:
            logger.error(f"Error setting shortname for project {project}: {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        serializer = serializers.ProjectInfoSerializer(
            instance=projectinfo, context={"request": request}
        )

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["PUT"])
    def set_allowed_destinations(self, request, project=None):
        try:
            allowed_destinations = str(request.data["allowed_destinations"])
        except Exception as e:
            logger.error(f"You must provide the 'allowed_destinations' field: {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            projectinfo = self._get(project)
        except Exception as e:
            logger.error(f"Error retrieving project {project}: {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)

        project = projectinfo.project

        if not request.user.is_staff:
            logger.error(
                f"User {request.user} is not allowed to set allowed_destinations for project {project}"
            )
            return Response(status=status.HTTP_403_FORBIDDEN)

        try:
            projectinfo.set_allowed_destinations(allowed_destinations)
            projectinfo.save()
        except Exception as e:
            logger.error(
                f"Error setting allowed_destinations for project {project}: {e}"
            )
            return Response(status=status.HTTP_400_BAD_REQUEST)

        serializer = serializers.ProjectInfoSerializer(
            instance=projectinfo, context={"request": request}
        )

        return Response(serializer.data, status=status.HTTP_200_OK)


def user_is_service_provider_owner_or_service_provider_manager(
    request, view, obj: models.ManagedProject | None = None
):
    if not obj:
        return

    if _has_owner_access(request.user, obj.project_class.customer):
        return

    if obj.project_class.customer.has_user(
        request.user, role=ServiceProviderRole.MANAGER
    ):
        return

    raise PermissionDenied()


class ManagedProjectViewSet(core_views.ActionsViewSet):
    queryset = models.ManagedProject.objects.all()
    approve_permissions = reject_permissions = [
        user_is_service_provider_owner_or_service_provider_manager
    ]
    serializer_class = serializers.ManagedProjectSerializer
    filter_backends = [GenericRoleFilter, DjangoFilterBackend]
    filterset_class = filters.ManagedProjectFilter

    disabled_actions = ["create", "destroy", "update", "partial_update"]
    lookup_field = "uuid"

    @extend_schema(
        request=ReviewCommentSerializer,
        responses=None,
        description="Approve project update request",
    )
    @action(detail=True, methods=["post"])
    def approve(self, request, **kwargs):
        review_request: models.ManagedProject = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        comment = serializer.validated_data.get("comment")
        review_request.approve(request.user, comment)
        return Response(status=status.HTTP_200_OK)

    @extend_schema(
        request=ReviewCommentSerializer,
        responses=None,
        description="Reject project update request",
    )
    @action(detail=True, methods=["post"])
    def reject(self, request, **kwargs):
        review_request: models.ManagedProject = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        comment = serializer.validated_data.get("comment")
        review_request.reject(request.user, comment)
        return Response(status=status.HTTP_200_OK)

    approve_serializer_class = reject_serializer_class = ReviewCommentSerializer
    approve_validators = reject_validators = [
        StateValidator(ReviewStates.PENDING, state_enum=ReviewStates)
    ]
