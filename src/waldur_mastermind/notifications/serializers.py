from rest_framework import serializers

from waldur_core.core import serializers as core_serializers
from waldur_core.core.serializers import (
    AugmentedSerializerMixin,
    RestrictedSerializerMixin,
)
from waldur_core.structure.models import Customer
from waldur_mastermind.marketplace.models import Offering
from waldur_mastermind.proposal.enums import ProposalStates
from waldur_mastermind.proposal.models import Round

from . import models, utils


class IdNamePairSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    uuid = serializers.UUIDField(required=True)


class QueryOutputSerializer(serializers.Serializer):
    customers = IdNamePairSerializer(many=True, required=False)
    offerings = IdNamePairSerializer(many=True, required=False)
    all_users = serializers.BooleanField(required=False)
    rounds = IdNamePairSerializer(many=True, required=False)
    proposal_states = serializers.ListField(
        child=serializers.CharField(), required=False
    )
    proposal_teams = serializers.BooleanField(required=False)
    reviewers = serializers.BooleanField(required=False)


class BroadcastMessageQuerySerializer(serializers.Serializer):
    customers = serializers.SlugRelatedField(
        slug_field="uuid",
        queryset=Customer.objects.all(),
        many=True,
        required=False,
    )
    offerings = serializers.SlugRelatedField(
        slug_field="uuid",
        queryset=Offering.objects.all(),
        many=True,
        required=False,
    )
    all_users = serializers.BooleanField(default=False)
    rounds = serializers.SlugRelatedField(
        slug_field="uuid",
        queryset=Round.objects.all(),
        many=True,
        required=False,
        help_text="Proposal rounds whose applicants (and, optionally, "
        "reviewers) receive the message.",
    )
    proposal_states = serializers.ListField(
        child=serializers.ChoiceField(
            choices=[state for state, _label in ProposalStates.CHOICES]
        ),
        required=False,
        help_text="Only the rounds' proposals in these states, e.g. draft to "
        "remind those who have not submitted. All states if empty.",
    )
    proposal_teams = serializers.BooleanField(
        default=True,
        help_text="Whether the rounds' proposal teams receive the message.",
    )
    reviewers = serializers.BooleanField(
        default=False,
        help_text="Whether the reviewers of the rounds' proposals receive the message.",
    )


def format_options(options):
    return [{"name": option.name, "uuid": option.uuid.hex} for option in options]


def serialize_query(query):
    serialized_query = {}
    if "customers" in query:
        serialized_query["customers"] = format_options(query["customers"])
    if "offerings" in query:
        serialized_query["offerings"] = format_options(query["offerings"])
    serialized_query["all_users"] = query.get("all_users", False)
    if query.get("rounds"):
        serialized_query["rounds"] = format_options(query["rounds"])
        serialized_query["proposal_states"] = list(query.get("proposal_states", []))
        serialized_query["proposal_teams"] = query.get("proposal_teams", True)
        serialized_query["reviewers"] = query.get("reviewers", False)
    return serialized_query


class BroadcastMessageSerializer(
    RestrictedSerializerMixin, serializers.ModelSerializer
):
    query = QueryOutputSerializer(read_only=True)
    author_full_name = serializers.ReadOnlyField(source="author.full_name")
    state = serializers.ReadOnlyField()
    emails = serializers.ReadOnlyField()

    class Meta:
        model = models.BroadcastMessage
        fields = (
            "uuid",
            "created",
            "subject",
            "body",
            "query",
            "author_full_name",
            "emails",
            "state",
            "send_at",
        )


class BroadcastMessageCreateSerializer(
    RestrictedSerializerMixin, serializers.ModelSerializer
):
    query = BroadcastMessageQuerySerializer(write_only=True)

    class Meta:
        model = models.BroadcastMessage
        fields = (
            "uuid",
            "created",
            "subject",
            "body",
            "query",
            "send_at",
        )

    def create(self, validated_data):
        current_user = self.context["request"].user
        validated_data["author"] = current_user
        query = validated_data.get("query", {})
        validated_data["emails"] = utils.get_user_emails_for_query(query)
        validated_data["query"] = serialize_query(query)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        query = validated_data.get("query", {})
        validated_data["emails"] = utils.get_user_emails_for_query(query)
        validated_data["query"] = serialize_query(query)
        return super().update(instance, validated_data)


class MessageTemplateSerializer(
    serializers.HyperlinkedModelSerializer,
):
    subject = core_serializers.HTMLCleanField()
    body = core_serializers.HTMLCleanField()

    class Meta:
        model = models.MessageTemplate
        fields = (
            "url",
            "uuid",
            "name",
            "subject",
            "body",
        )
        extra_kwargs = {"url": {"lookup_field": "uuid"}}


class AdminAnnouncementSerializer(
    AugmentedSerializerMixin, RestrictedSerializerMixin, serializers.ModelSerializer
):
    class Meta:
        model = models.AdminAnnouncement
        fields = (
            "uuid",
            "description",
            "active_from",
            "active_to",
            "is_active",
            "type",
            "created",
        )


class NotificationRecipientOfferingSerializer(serializers.Serializer):
    uuid = serializers.UUIDField()
    name = serializers.CharField()


class NotificationRecipientCustomerSerializer(serializers.Serializer):
    uuid = serializers.UUIDField()
    name = serializers.CharField()


class NotificationRecipientSerializer(serializers.Serializer):
    full_name = serializers.CharField(required=False, allow_null=True)
    email = serializers.EmailField()
    offerings = NotificationRecipientOfferingSerializer(many=True)
    customers = NotificationRecipientCustomerSerializer(many=True)
