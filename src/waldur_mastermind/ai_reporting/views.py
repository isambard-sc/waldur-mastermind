from drf_spectacular.utils import extend_schema
from rest_framework import decorators, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from waldur_core.core import permissions as core_permissions
from waldur_core.core.views import ActionsViewSet
from waldur_core.structure import permissions as structure_permissions
from waldur_mastermind.ai_reporting import serializers, tasks
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession


class ReportingMessageViewSet(ActionsViewSet):
    """Ask the AI reporting harness a question and poll for its answer.

    Messages are created only via `ask` - direct create/update/destroy are
    disabled so a client can never fabricate a message's status/answer or
    bypass the harness call entirely.
    """

    queryset = ReportingMessage.objects.all().select_related("session__user")
    serializer_class = serializers.ReportingMessageSerializer
    lookup_field = "uuid"
    http_method_names = ["get", "post", "options"]
    permission_classes = [IsAuthenticated, core_permissions.ActionsPermission]
    disabled_actions = ["create", "update", "partial_update", "destroy"]

    def get_queryset(self):
        # Staff/support-scoped feature (see ask_permissions), but each user -
        # staff included - only ever sees their own AI reporting history here.
        # This view makes no claim about who may use the feature; that's
        # ask_permissions' job.
        return super().get_queryset().filter(session__user=self.request.user)

    list_permissions = [structure_permissions.is_staff_or_support]
    retrieve_permissions = [structure_permissions.is_staff_or_support]
    ask_permissions = [structure_permissions.is_staff_or_support]
    ask_serializer_class = serializers.AskRequestSerializer

    @extend_schema(
        summary="Ask the AI reporting harness a question",
        description=(
            "Creates (or reuses, with new_session=false) the caller's AI reporting "
            "session, enqueues the question for the harness, and returns immediately - "
            "poll the returned message's detail endpoint for the answer, since a "
            "single question can take several minutes."
        ),
        responses={202: serializers.ReportingMessageSerializer},
    )
    @decorators.action(detail=False, methods=["post"])
    def ask(self, request):
        request_serializer = self.get_serializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        prompt = request_serializer.validated_data["prompt"]
        new_session = request_serializer.validated_data["new_session"]

        session, _created = ReportingSession.objects.get_or_create(user=request.user)

        # Avoid piling up a second Celery task for the same conversation if the
        # caller submits again before the first answer lands - the harness's own
        # per-identity lock would serialize them anyway, but there's no reason to
        # queue redundant work (or redundant Bedrock cost) for it.
        existing_pending = session.messages.filter(
            status=ReportingMessage.Status.PENDING
        ).first()
        if existing_pending is not None and not new_session:
            return Response(
                serializers.ReportingMessageSerializer(existing_pending).data,
                status=status.HTTP_202_ACCEPTED,
            )

        message = ReportingMessage.objects.create(session=session, prompt=prompt)
        tasks.ask_harness.delay(message.pk, new_session=new_session)

        return Response(
            serializers.ReportingMessageSerializer(message).data,
            status=status.HTTP_202_ACCEPTED,
        )
