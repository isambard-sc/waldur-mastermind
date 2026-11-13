import uuid
from datetime import timedelta

from django.db import transaction
from django.db.models import Count, Max, Prefetch, Sum
from django.db.models.functions import TruncDate
from django.utils import timezone
from drf_spectacular.utils import (
    OpenApiParameter,
    extend_schema,
    extend_schema_view,
)
from rest_framework import decorators, status, views
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from waldur_core.core import permissions as core_permissions
from waldur_core.core.views import ActionsViewSet, ConstanceCheckExtensionMixin
from waldur_core.structure import permissions as structure_permissions
from waldur_mastermind.ai_reporting import limits, permissions, serializers, tasks
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingFile,
    ReportingMessage,
    ReportingSession,
    ReportingUsageRecord,
)

_USAGE_STATS_MAX_DAYS = 365
_USAGE_STATS_DEFAULT_DAYS = 30


@extend_schema_view(
    list=extend_schema(
        parameters=[
            OpenApiParameter(
                "session",
                uuid.UUID,
                OpenApiParameter.QUERY,
                description="Filter to one of the caller's own AI reporting sessions.",
            ),
        ]
    )
)
class ReportingMessageViewSet(ConstanceCheckExtensionMixin, ActionsViewSet):
    """Ask the AI reporting harness a question and poll for its answer.

    Messages are only created via `ask`, so a client can't fabricate a
    status or answer. Every action returns 424 while AI_REPORTING_ENABLED is
    off, and all but usage_stats are limited to AI_REPORTING_ENABLED_ROLES.
    """

    extension_name = "AI_REPORTING"

    queryset = ReportingMessage.objects.all().select_related("session__user")
    serializer_class = serializers.ReportingMessageSerializer
    lookup_field = "uuid"
    http_method_names = ["get", "post", "options"]
    permission_classes = [IsAuthenticated, core_permissions.ActionsPermission]
    disabled_actions = ["create", "update", "partial_update", "destroy"]

    def get_queryset(self):
        # Everyone, staff included, only sees their own messages.
        queryset = super().get_queryset().filter(session__user=self.request.user)

        # Lets the frontend restore a single conversation.
        session_uuid = self.request.query_params.get("session", "")
        if session_uuid:
            queryset = queryset.filter(session__uuid=session_uuid)

        return queryset

    list_permissions = [permissions.check_enabled_roles]
    retrieve_permissions = [permissions.check_enabled_roles]
    ask_permissions = [permissions.check_enabled_roles]
    ask_serializer_class = serializers.AskRequestSerializer

    @extend_schema(
        summary="Ask the AI reporting harness a question",
        description=(
            "Queues the question and returns immediately - poll the returned "
            "message for the answer. Pass 'session' to continue a conversation or "
            "'new_session' to start one; with neither, the latest session is reused."
        ),
        responses={202: serializers.ReportingMessageSerializer},
    )
    @decorators.action(detail=False, methods=["post"])
    def ask(self, request):
        request_serializer = self.get_serializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)

        # 429 before anything is created if a usage limit is reached.
        limits.enforce_usage_limits(request.user)

        prompt = request_serializer.validated_data["prompt"]
        new_session = request_serializer.validated_data["new_session"]
        requested_session = request_serializer.validated_data["session"]

        if new_session:
            session = ReportingSession.objects.create(user=request.user)
        elif requested_session is not None:
            # 404, not 403, so we don't reveal that someone else's session exists.
            if requested_session.user_id != request.user.id:
                raise NotFound()
            session = requested_session
        else:
            session = ReportingSession.objects.filter(user=request.user).order_by(
                "-created"
            ).first() or ReportingSession.objects.create(user=request.user)

        # Don't queue a second task while this conversation has one pending.
        existing_pending = session.messages.filter(
            status=ReportingMessage.Status.PENDING
        ).first()
        # Passes the request so file URLs come out absolute.
        context = self.get_serializer_context()

        if existing_pending is not None:
            return Response(
                serializers.ReportingMessageSerializer(
                    existing_pending, context=context
                ).data,
                status=status.HTTP_202_ACCEPTED,
            )

        message = ReportingMessage.objects.create(session=session, prompt=prompt)
        tasks.ask_harness.delay(message.pk)

        return Response(
            serializers.ReportingMessageSerializer(message, context=context).data,
            status=status.HTTP_202_ACCEPTED,
        )

    # Staff/support only, whatever AI_REPORTING_ENABLED_ROLES says - other
    # users' usage is more sensitive than being able to use the tool.
    usage_stats_permissions = [structure_permissions.is_staff_or_support]
    usage_stats_serializer_class = serializers.UsageStatsResponseSerializer

    @extend_schema(
        summary="Site-wide AI reporting token usage",
        description=(
            "Token usage totals and a daily trend across all users, not just the caller."
        ),
        parameters=[
            OpenApiParameter(
                "days",
                int,
                location=OpenApiParameter.QUERY,
                description=f"Trailing window in days (1-{_USAGE_STATS_MAX_DAYS}, default {_USAGE_STATS_DEFAULT_DAYS}).",
            ),
        ],
        responses={200: serializers.UsageStatsResponseSerializer},
    )
    @decorators.action(detail=False, methods=["get"])
    def usage_stats(self, request):
        try:
            days = int(request.query_params.get("days", _USAGE_STATS_DEFAULT_DAYS))
        except ValueError:
            days = _USAGE_STATS_DEFAULT_DAYS
        days = max(1, min(days, _USAGE_STATS_MAX_DAYS))
        since = timezone.now() - timedelta(days=days)

        # Site-wide, so not self.get_queryset(). Reads ReportingUsageRecord,
        # which outlives message retention cleanup.
        queryset = ReportingUsageRecord.objects.filter(created__gte=since)

        totals = queryset.aggregate(
            total_input_tokens=Sum("input_tokens"),
            total_output_tokens=Sum("output_tokens"),
            total_requests=Count("id"),
        )

        daily = list(
            queryset.annotate(date=TruncDate("created"))
            .values("date")
            .annotate(
                input_tokens=Sum("input_tokens"),
                output_tokens=Sum("output_tokens"),
                requests=Count("id"),
            )
            .order_by("date")
        )

        by_user = [
            {
                "user": row["user__uuid"],
                "full_name": f"{row['user__first_name']} {row['user__last_name']}".strip(),
                "username": row["user__username"],
                "input_tokens": row["input_tokens"],
                "output_tokens": row["output_tokens"],
                "requests": row["requests"],
            }
            for row in queryset.values(
                "user__uuid",
                "user__username",
                "user__first_name",
                "user__last_name",
            )
            .annotate(
                input_tokens=Sum("input_tokens"),
                output_tokens=Sum("output_tokens"),
                requests=Count("id"),
            )
            .order_by("-input_tokens")
        ]

        response_data = {
            "period_days": days,
            "total_input_tokens": totals["total_input_tokens"] or 0,
            "total_output_tokens": totals["total_output_tokens"] or 0,
            "total_requests": totals["total_requests"] or 0,
            "daily": daily,
            "by_user": by_user,
        }
        return Response(serializers.UsageStatsResponseSerializer(response_data).data)


class ReportingSessionViewSet(ConstanceCheckExtensionMixin, ActionsViewSet):
    """The caller's own conversations, most recently active first. Read-only -
    sessions are created by ReportingMessageViewSet.ask. Sessions whose
    messages have all been cleaned up are hidden."""

    extension_name = "AI_REPORTING"

    queryset = ReportingSession.objects.all()
    serializer_class = serializers.ReportingSessionSerializer
    lookup_field = "uuid"
    http_method_names = ["get", "options"]
    permission_classes = [IsAuthenticated, core_permissions.ActionsPermission]

    def get_queryset(self):
        return (
            ReportingSession.objects.filter(user=self.request.user)
            .annotate(
                last_activity=Max("messages__created"),
                message_count=Count("messages"),
            )
            .filter(message_count__gt=0)
            .prefetch_related(
                Prefetch(
                    "messages",
                    queryset=ReportingMessage.objects.order_by("created"),
                    to_attr="ordered_messages",
                )
            )
            .order_by("-last_activity")
        )

    list_permissions = [permissions.check_enabled_roles]
    retrieve_permissions = [permissions.check_enabled_roles]


class ReportingFileViewSet(ConstanceCheckExtensionMixin, ActionsViewSet):
    """The caller's own files across all sessions, so one can be found or
    deleted without digging through the chat. Files are also deleted
    automatically after AI_REPORTING_FILE_RETENTION_DAYS."""

    extension_name = "AI_REPORTING"

    queryset = ReportingFile.objects.all().select_related("message__session__user")
    serializer_class = serializers.ReportingFileListSerializer
    lookup_field = "uuid"
    http_method_names = ["get", "delete", "options"]
    permission_classes = [IsAuthenticated, core_permissions.ActionsPermission]

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .filter(message__session__user=self.request.user)
            .order_by("-created")
        )

    list_permissions = [permissions.check_enabled_roles]
    retrieve_permissions = [permissions.check_enabled_roles]
    destroy_permissions = [permissions.check_enabled_roles]


class HarnessConnectionView(views.APIView):
    """The site's AI reporting harness connection. Staff may change it;
    support may read it."""

    permission_classes = (IsAuthenticated,)

    def _check(self, request):
        permissions.is_staff_or_support_for_reads(request, self)

    @extend_schema(
        operation_id="ai_reporting_harness_connection_retrieve",
        responses=serializers.HarnessConnectionSerializer,
    )
    def get(self, request):
        self._check(request)
        serializer = serializers.HarnessConnectionSerializer(HarnessConnection.get())
        return Response(serializer.data)

    @extend_schema(
        operation_id="ai_reporting_harness_connection_partial_update",
        request=serializers.HarnessConnectionSerializer,
        responses=serializers.HarnessConnectionSerializer,
    )
    def patch(self, request):
        self._check(request)
        with transaction.atomic():
            connection = HarnessConnection.objects.select_for_update().get(
                pk=HarnessConnection.get().pk
            )
            serializer = serializers.HarnessConnectionSerializer(
                connection,
                data=request.data,
                partial=True,
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
        return Response(serializer.data)
