from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import decorators, permissions, status
from rest_framework.response import Response

from waldur_core.core import permissions as core_permissions
from waldur_core.core import validators as core_validators
from waldur_core.core.views import ActionsViewSet

from . import filters, models, serializers, tasks, utils


class BroadcastMessageViewSet(ActionsViewSet):
    queryset = models.BroadcastMessage.objects.all().order_by("-created")
    serializer_class = serializers.BroadcastMessageSerializer
    permission_classes = [permissions.IsAuthenticated, core_permissions.IsSupport]
    filter_backends = [DjangoFilterBackend]
    filterset_class = filters.BroadcastMessageFilterSet
    update_validators = destroy_validators = [
        core_validators.StateValidator(
            models.BroadcastMessage.States.DRAFT,
            models.BroadcastMessage.States.SCHEDULED,
        )
    ]
    lookup_field = "uuid"

    @extend_schema(request=None, responses=None)
    @decorators.action(detail=True, methods=["post"])
    def send(self, request, *args, **kwargs):
        broadcast_message: models.BroadcastMessage = self.get_object()
        tasks.send_broadcast_message_email.delay(broadcast_message.uuid)
        return Response(status=status.HTTP_202_ACCEPTED)

    @extend_schema(request=None, responses=None)
    @decorators.action(detail=True, methods=["post"])
    def schedule(self, request, *args, **kwargs):
        broadcast_message: models.BroadcastMessage = self.get_object()
        broadcast_message.state = models.BroadcastMessage.States.SCHEDULED
        broadcast_message.save(update_fields=["state"])
        return Response(status=status.HTTP_200_OK)

    @extend_schema(request=serializers.QuerySerializer)
    @decorators.action(detail=False)
    def recipients(self, request, *args, **kwargs):
        serializer = serializers.QuerySerializer(
            context=self.get_serializer_context(), data=request.query_params
        )
        serializer.is_valid(raise_exception=True)
        # Pass request object for send_to_me functionality
        query_data = serializer.validated_data.copy()
        query_data["_request"] = request
        users = utils.get_recipients_for_query(query_data)
        paginated_result = self.paginate_queryset(users)
        return self.get_paginated_response(paginated_result)

    @extend_schema(
        request={"multipart/form-data": {"type": "object"}},
        responses={status.HTTP_201_CREATED: serializers.BroadcastMessageAttachmentSerializer},
    )
    @decorators.action(detail=True, methods=["post"])
    def attach_file(self, request, uuid=None):
        """Attach a file to a broadcast message."""
        broadcast_message = self.get_object()

        if "file" not in request.FILES:
            return Response(
                {"detail": "No file provided"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        uploaded_file = request.FILES["file"]

        attachment = models.BroadcastMessageAttachment.objects.create(
            broadcast_message=broadcast_message,
            file=uploaded_file,
            filename=uploaded_file.name,
            size=uploaded_file.size,
            uploaded_by=request.user,
        )

        serializer = serializers.BroadcastMessageAttachmentSerializer(
            attachment, context={"request": request}
        )
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    attach_file_validators = [
        core_validators.StateValidator(
            models.BroadcastMessage.States.DRAFT,
            models.BroadcastMessage.States.SCHEDULED,
        )
    ]

    @extend_schema(
        request={"application/json": {"type": "object", "properties": {"uuid": {"type": "string"}}}},
        responses={status.HTTP_204_NO_CONTENT: None},
    )
    @decorators.action(detail=True, methods=["post"])
    def detach_file(self, request, uuid=None):
        """Detach a file from a broadcast message."""
        broadcast_message = self.get_object()

        attachment_uuid = request.data.get("uuid")
        if not attachment_uuid:
            return Response(
                {"detail": "Attachment UUID is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            attachment = models.BroadcastMessageAttachment.objects.get(
                uuid=attachment_uuid,
                broadcast_message=broadcast_message,
            )
            attachment.file.delete(save=False)
            attachment.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except models.BroadcastMessageAttachment.DoesNotExist:
            return Response(
                {"detail": "Attachment not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

    detach_file_validators = [
        core_validators.StateValidator(
            models.BroadcastMessage.States.DRAFT,
            models.BroadcastMessage.States.SCHEDULED,
        )
    ]


class MessageTemplateViewSet(ActionsViewSet):
    queryset = models.MessageTemplate.objects.all().order_by("name")
    serializer_class = serializers.MessageTemplateSerializer
    permission_classes = [permissions.IsAuthenticated, core_permissions.IsSupport]
    filter_backends = [DjangoFilterBackend]
    filterset_class = filters.MessageTemplateFilterSet
    lookup_field = "uuid"


class AdminAnnouncementViewSet(ActionsViewSet):
    queryset = models.AdminAnnouncement.objects.all().order_by("-created")
    serializer_class = serializers.AdminAnnouncementSerializer
    permission_classes = [core_permissions.IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend]
    filterset_class = filters.AdminAnnouncementFilterSet
    lookup_field = "uuid"
