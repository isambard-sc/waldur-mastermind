import logging

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.utils.translation import ugettext_lazy as _
from jira import JIRAError
from rest_framework import exceptions as rf_exceptions
from rest_framework import status
from rest_framework.response import Response

from waldur_core.core import utils as core_utils
from waldur_core.core import views as core_views
from waldur_mastermind.marketplace import models as marketplace_models
from waldur_mastermind.marketplace_support.utils import (
    format_description,
    get_request_link,
)
from waldur_mastermind.support import backend as support_backend
from waldur_mastermind.support import exceptions as support_exceptions
from waldur_mastermind.support import executors as support_executors
from waldur_mastermind.support import models as support_models
from waldur_mastermind.support import serializers as support_serializers
from waldur_mastermind.support import views as support_views

from . import serializers

logger = logging.getLogger(__name__)


def create_issue(order_item, description, summary):
    order_item_content_type = ContentType.objects.get_for_model(order_item)

    if not support_models.Issue.objects.filter(
        resource_object_id=order_item.id, resource_content_type=order_item_content_type
    ).exists():
        issue_details = dict(
            caller=order_item.order.created_by,
            project=order_item.order.project,
            customer=order_item.order.project.customer,
            type=settings.WALDUR_SUPPORT['DEFAULT_OFFERING_ISSUE_TYPE'],
            description=description,
            summary=summary,
            resource=order_item,
        )
        issue_details['summary'] = support_serializers.render_issue_template(
            'summary', issue_details
        )
        issue_details['description'] = support_serializers.render_issue_template(
            'description', issue_details
        )
        issue = support_models.Issue.objects.create(**issue_details)
        try:
            support_backend.get_active_backend().create_issue(issue)
        except support_exceptions.SupportUserInactive:
            issue.delete()
            order_item.resource.set_state_erred()
            order_item.resource.save(update_fields=['state'])
            raise rf_exceptions.ValidationError(
                _(
                    'Delete resource process is cancelled and issue not created '
                    'because a caller is inactive.'
                )
            )
        else:
            ids = marketplace_models.OrderItem.objects.filter(
                resource=order_item.resource
            ).values_list('id', flat=True)
            linked_issues = support_models.Issue.objects.filter(
                resource_object_id__in=ids,
                resource_content_type=order_item_content_type,
            ).exclude(id=issue.id)
            try:
                support_backend.get_active_backend().create_issue_links(
                    issue, list(linked_issues)
                )
            except JIRAError as e:
                logger.exception('Linked issues have not been added: %s', e)
    else:
        message = (
            'An issue creating is skipped because an issue for order item %s exists already.'
            % order_item.uuid
        )
        logger.warning(message)


class IssueViewSet(core_views.ActionsViewSet):
    def update(self, request, *args, **kwargs):
        uuid = request.data['uuid']
        order_item = marketplace_models.OrderItem.objects.get(uuid=uuid)
        summary = 'Request to switch plan for %s' % order_item.resource.scope.name
        request_url = get_request_link(order_item.resource.scope)
        description = format_description(
            'UPDATE_RESOURCE_TEMPLATE',
            {'order_item': order_item, 'request_url': request_url,},
        )
        create_issue(order_item, description, summary)
        return Response(status=status.HTTP_202_ACCEPTED)

    def destroy(self, request, uuid, *args, **kwargs):
        order_item = marketplace_models.OrderItem.objects.get(uuid=uuid)
        summary = 'Request to terminate resource %s' % order_item.resource.scope.name
        request_url = get_request_link(order_item.resource.scope)
        description = format_description(
            'TERMINATE_RESOURCE_TEMPLATE',
            {'order_item': order_item, 'request_url': request_url,},
        )
        create_issue(order_item, description, summary)
        return Response(status=status.HTTP_202_ACCEPTED)


class OfferingViewSet(support_views.OfferingViewSet):
    create_serializer_class = serializers.OfferingCreateSerializer

    @transaction.atomic()
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        offering = serializer.save()

        comment_tmpl = None
        order_item = request.data.get('order_item')
        if order_item:
            order_item = core_utils.deserialize_instance(order_item)
            comment_tmpl = order_item.offering.secret_options.get(
                'template_confirmation_comment'
            )

        support_executors.IssueCreateExecutor.execute(
            offering.issue, comment_tmpl=comment_tmpl
        )
        return Response(serializer.data, status=status.HTTP_201_CREATED)
