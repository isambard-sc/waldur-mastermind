from datetime import timedelta

from django.db.models import Count, Sum
from django.db.models.functions import TruncDate
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import decorators, status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from waldur_core.core import permissions as core_permissions
from waldur_core.core.views import ActionsViewSet, ConstanceCheckExtensionMixin
from waldur_core.structure import permissions as structure_permissions
from waldur_mastermind.ai_reporting import limits, serializers, tasks
from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingSession

_USAGE_STATS_MAX_DAYS = 365
_USAGE_STATS_DEFAULT_DAYS = 30


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

        # Reject before creating anything if this would exceed a configured
        # AI_REPORTING_TOKEN_LIMIT_*/GLOBAL_* Constance limit - see
        # ai_reporting.limits. Raises rest_framework.exceptions.Throttled
        # (429) directly; DRF's own exception handling turns that into the
        # response.
        limits.enforce_usage_limits(request.user)

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

    usage_stats_permissions = [structure_permissions.is_staff_or_support]
    usage_stats_serializer_class = serializers.UsageStatsResponseSerializer

    @extend_schema(
        summary="Site-wide AI reporting token usage",
        description=(
            "Token usage totals and a daily trend across every user's AI reporting "
            "questions - not scoped to the caller's own messages, unlike every other "
            "action on this viewset. For staff/allocators to see actual usage, since "
            "that's a more direct answer to 'does this cost a lot' than a policy limit "
            "alone."
        ),
        parameters=[
            OpenApiParameter(
                "days", int, location=OpenApiParameter.QUERY,
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

        # Deliberately not self.get_queryset() - that's filtered to the
        # caller's own messages (see get_queryset's own docstring); this is
        # the one action in this viewset that is site-wide by design.
        queryset = ReportingMessage.objects.filter(created__gte=since)

        totals = queryset.aggregate(
            total_input_tokens=Sum("input_tokens"),
            total_output_tokens=Sum("output_tokens"),
            total_requests=Count("id"),
        )

        daily = list(
            queryset
            .annotate(date=TruncDate("created"))
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
                "user": row["session__user__uuid"],
                "full_name": f"{row['session__user__first_name']} {row['session__user__last_name']}".strip(),
                "username": row["session__user__username"],
                "input_tokens": row["input_tokens"],
                "output_tokens": row["output_tokens"],
                "requests": row["requests"],
            }
            for row in queryset
            .values(
                "session__user__uuid", "session__user__username",
                "session__user__first_name", "session__user__last_name",
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
