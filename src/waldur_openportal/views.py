import logging

from django.utils.translation import gettext_lazy as _
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, response, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from waldur_core.core import executors as core_executors
from waldur_core.structure import filters as structure_filters
from waldur_core.structure import permissions as structure_permissions
from waldur_core.structure import views as structure_views
from waldur_core.core import views as core_views
from waldur_core.core import models as core_models

from waldur_core.core.permissions import IsAdminOrReadOnly
from waldur_core.structure.permissions import IsAdminOrOwner

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


class AllocationUserUsageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = models.AllocationUserUsage.objects.all().order_by("year", "month")
    serializer_class = serializers.AllocationUserUsageSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)
    filterset_class = filters.AllocationUserUsageFilter


class AssociationViewSet(viewsets.ReadOnlyModelViewSet):
    lookup_field = "uuid"
    queryset = models.Association.objects.all().order_by("username")
    serializer_class = serializers.AssociationSerializer
    permission_classes = (permissions.IsAuthenticated,)
    filter_backends = (structure_filters.GenericRoleFilter, DjangoFilterBackend)
    filterset_class = filters.AssociationFilter


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

        serializer = serializers.UserInfoSerializer(instance=userinfo,
                                                    context={"request": request})

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["PUT"])
    def set_shortname(self, request, user=None):
        logger.info(f"Setting shortname for user {user} : {request}")

        try:
            userinfo = self._get(user)
        except Exception as e:
            logger.error(f"Error retrieving user {user}: {e}")
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = serializers.UserInfoModifySerializer(userinfo, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class ProjectInfoViewSet(core_views.ActionsViewSet):
    queryset = models.ProjectInfo.objects.all().order_by("shortname")
    lookup_field = "project"
    serializer_class = serializers.ProjectInfoSerializer
    permission_classes = [IsAdminOrReadOnly]
    filterset_class = filters.ProjectInfoFilter

    def create(self, request):
        serializer = serializers.ProjectInfoModifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        projectinfo = serializer.save()
        serializer = serializers.ProjectInfoSerializer(instance=projectinfo)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, **kwargs):
        instance = self.get_object()
        serializer = serializers.ProjectInfoModifySerializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        projectinfo = serializer.save()
        serializer = serializers.ProjectInfoSerializer(instance=projectinfo)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["PUT"])
    def update_shortname(self, request, project=None):
        instance = self.get_object()
        serializer = serializers.ProjectInfoModifySerializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["PUT"])
    def update_allowed_destinations(self, request, project=None):
        instance = self.get_object()
        serializer = serializers.ProjectInfoModifySerializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
