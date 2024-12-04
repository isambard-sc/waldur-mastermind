import logging

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django_fsm import TransitionNotAllowed
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from waldur_core.core import views as core_views
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace import permissions
from waldur_mastermind.marketplace import serializers as marketplace_serializers
from waldur_openportal import models as openportal_models
from waldur_openportal import serializers as openportal_serializers

from . import PLUGIN_NAME, serializers

logger = logging.getLogger(__name__)

User = get_user_model()


class OpenPortalViewSet(core_views.ActionsViewSet):
    lookup_field = "uuid"
    queryset = marketplace_models.Resource.objects.filter(
        offering__type=PLUGIN_NAME
    ).exclude(object_id=None)
    serializer_class = marketplace_serializers.ResourceSerializer
    disabled_actions = [
        "retrieve",
        "list",
        "create",
        "update",
        "partial_update",
        "destroy",
    ]

    @action(detail=True, methods=["post"])
    def set_limits(self, request, uuid=None):
        resource = self.get_object()
        allocation: openportal_models.Allocation = resource.scope

        new_limits = request.data

        if not isinstance(new_limits, dict):
            limits_type = type(new_limits)
            raise ValidationError(
                _("The payload must have dictionary type, not %s." % limits_type)
            )

        old_limits = resource.limits
        resource.limits = request.data
        resource.save(update_fields=["limits"])

        logger.info(
            "The limits for allocation %s have been changed from %s to %s",
            allocation,
            old_limits,
            request.data,
        )

        return Response(
            {"status": _("Limits are successfully set.")},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["POST"])
    def set_usage(self, request, uuid=None):
        resource = self.get_object()
        allocation: openportal_models.Allocation = resource.scope
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data
        if payload["username"] == "TOTAL_ACCOUNT_USAGE":
            allocation.cpu_usage = payload["cpu_usage"]
            allocation.gpu_usage = payload["gpu_usage"]
            allocation.ram_usage = payload["ram_usage"]
            allocation.save(update_fields=["cpu_usage", "gpu_usage", "ram_usage"])
            logger.info(
                "The total usage for allocation %s has been set: %s.",
                allocation,
                payload,
            )
        else:
            (
                user_usage,
                created,
            ) = openportal_models.AllocationUserUsage.objects.update_or_create(
                allocation=allocation,
                user=payload["user"],
                username=payload["username"],
                month=payload["month"],
                year=payload["year"],
                defaults={
                    "cpu_usage": payload["cpu_usage"],
                    "ram_usage": payload["ram_usage"],
                    "gpu_usage": payload["gpu_usage"],
                },
            )
            if created:
                logger.info(
                    "User usage %s has been created with the following params: %s",
                    user_usage,
                    payload,
                )
            else:
                logger.info(
                    "User usage %s has been updated with the following params: %s",
                    user_usage,
                    payload,
                )

        return Response(
            {
                "detail": _("Allocation usage has been updated successfully."),
            },
            status=status.HTTP_200_OK,
        )

    set_usage_serializer_class = openportal_serializers.AllocationUserUsageCreateSerializer

    @action(detail=True, methods=["POST"])
    def set_state(self, request, uuid=None):
        resource = self.get_object()
        allocation: openportal_models.Allocation = resource.scope
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        state = serializer.validated_data["state"]

        state_to_methods_map = {
            "creating": "begin_creating",
            "updating": "begin_updating",
            "deletion_scheduled": "schedule_deleting",
            "update_scheduled": "schedule_updating",
            "deleting": "begin_deleting",
            "ok": "set_ok",
            "erred": "set_erred",
        }

        transition_method_name = state_to_methods_map.get(state)
        if not transition_method_name:
            raise ValidationError(
                _("Invalid state: a corresponding method for transition is absent")
            )
        try:
            transition_method = getattr(allocation, transition_method_name)
            transition_method()
            allocation.save(update_fields=["state"])
            return Response(
                {
                    "detail": _("Allocation state has been changed to %s" % state),
                },
                status.HTTP_200_OK,
            )
        except TransitionNotAllowed:
            return Response(
                {
                    "detail": _(
                        "Allocation state can not be changed from {} to {}.".format(
                            allocation.state, state
                        )
                    ),
                },
                status.HTTP_409_CONFLICT,
            )

    set_state_serializer_class = serializers.SetStateSerializer

    @action(detail=True, methods=["POST"])
    def set_backend_id(self, request, uuid=None):
        resource = self.get_object()
        allocation: openportal_models.Allocation = resource.scope
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_backend_id = serializer.validated_data["backend_id"]
        old_backend_id = allocation.backend_id
        if new_backend_id != old_backend_id:
            allocation.backend_id = serializer.validated_data["backend_id"]
            allocation.save(update_fields=["backend_id"])
            logger.info(
                "%s has changed backend_id from %s to %s",
                request.user.full_name,
                old_backend_id,
                new_backend_id,
            )

            return Response(
                {"status": _("Allocation backend_id has been changed.")},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": _("Allocation backend_id is not changed.")},
                status=status.HTTP_200_OK,
            )

    set_backend_id_serializer_class = serializers.SetBackendIdSerializer
