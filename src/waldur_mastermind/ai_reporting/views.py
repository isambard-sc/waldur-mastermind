from drf_spectacular.utils import extend_schema
from rest_framework import decorators, status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from waldur_core.core import permissions as core_permissions
from waldur_core.core.views import ActionsViewSet, ConstanceCheckExtensionMixin
from waldur_core.structure import permissions as structure_permissions
from waldur_mastermind.ai_reporting import serializers, tasks
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession


class ReportingMessageViewSet(ConstanceCheckExtensionMixin, ActionsViewSet):
    """Ask the AI reporting harness a question and poll for its answer.

    Messages are created only via `ask` - direct create/update/destroy are
    disabled so a client can never fabricate a message's status/answer or
    bypass the harness call entirely.

    ConstanceCheckExtensionMixin (same mechanism the chat app's
    LLMConfigurationMixin uses for AI_ASSISTANT_ENABLED) raises a 424 for
    every action - list and retrieve included, not just ask - while
    AI_REPORTING_ENABLED is off, matching that app's own convention of
    treating the whole feature as unavailable, not just the ability to ask
    something new.
    """

    extension_name = "AI_REPORTING"

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
            "Enqueues the question for the harness against one of the caller's AI "
            "reporting sessions (a user may have several, e.g. one per open browser "
            "tab) and returns immediately - poll the returned message's detail "
            "endpoint for the answer, since a single question can take several "
            "minutes. Pass 'session' to continue a specific one, or 'new_session' "
            "to start a fresh one; with neither, the most recently used session is "
            "reused (or created, for a first-time caller)."
        ),
        responses={202: serializers.ReportingMessageSerializer},
    )
    @decorators.action(detail=False, methods=["post"])
    def ask(self, request):
        request_serializer = self.get_serializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        prompt = request_serializer.validated_data["prompt"]
        new_session = request_serializer.validated_data["new_session"]
        requested_session = request_serializer.validated_data["session"]

        if new_session:
            session = ReportingSession.objects.create(user=request.user)
        elif requested_session is not None:
            # Don't reveal whether a foreign uuid exists at all - just 404 it,
            # the same way an owned-but-unknown uuid would 404.
            if requested_session.user_id != request.user.id:
                raise NotFound()
            session = requested_session
        else:
            session = (
                ReportingSession.objects.filter(user=request.user)
                .order_by("-created")
                .first()
                or ReportingSession.objects.create(user=request.user)
            )

        # Avoid piling up a second Celery task for the same conversation if the
        # caller submits again before the first answer lands - the harness's own
        # per-identity lock would serialize them anyway, but there's no reason to
        # queue redundant work (or redundant Bedrock cost) for it. A brand-new
        # session (new_session=True) never has a pending message of its own, so
        # this never fires for one.
        existing_pending = session.messages.filter(
            status=ReportingMessage.Status.PENDING
        ).first()
        # context carries the request, so ReportingFileSerializer.file (once
        # any exist) serializes to an absolute download URL - ask_serializer_class
        # overrides what self.get_serializer() builds for *input*, so the
        # response here is built explicitly instead, same as the response
        # schema in @extend_schema above.
        context = self.get_serializer_context()

        if existing_pending is not None:
            return Response(
                serializers.ReportingMessageSerializer(existing_pending, context=context).data,
                status=status.HTTP_202_ACCEPTED,
            )

        message = ReportingMessage.objects.create(session=session, prompt=prompt)
        tasks.ask_harness.delay(message.pk)

        return Response(
            serializers.ReportingMessageSerializer(message, context=context).data,
            status=status.HTTP_202_ACCEPTED,
        )
