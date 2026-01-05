from rest_framework import serializers

from waldur_core.core import serializers as core_serializers
from waldur_core.core.models import User
from waldur_core.core.serializers import (
    AugmentedSerializerMixin,
    RestrictedSerializerMixin,
)
from waldur_core.structure.models import Customer
from waldur_mastermind.marketplace.models import Offering

from . import models, utils


class QuerySerializer(serializers.Serializer):
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
    proposal_states = serializers.ListField(
        child=serializers.CharField(),
        required=False,
    )
    include_reviewers = serializers.BooleanField(default=False)
    send_to_me = serializers.BooleanField(default=False)
    additional_recipients = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
    )
    excluded_recipients = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Avoid circular import - set Round queryset dynamically
        try:
            from waldur_mastermind.proposal.models import Round

            self.fields["round"] = serializers.SlugRelatedField(
                slug_field="uuid",
                queryset=Round.objects.all(),
                required=False,
            )
        except ImportError:
            # proposal app not installed - make it read-only
            self.fields["round"] = serializers.SlugRelatedField(
                slug_field="uuid",
                read_only=True,
                required=False,
            )


def format_options(options):
    return [
        {"name": option.name, "uuid": option.uuid.hex} for option in options
    ]


def format_users(users):
    return [
        {
            "uuid": user.uuid.hex,
            "email": user.email,
            "full_name": user.full_name,
        }
        for user in users
    ]


def serialize_query(query):
    serialized_query = {}
    if "customers" in query:
        serialized_query["customers"] = format_options(query["customers"])
    if "offerings" in query:
        serialized_query["offerings"] = format_options(query["offerings"])
    serialized_query["all_users"] = query.get("all_users", False)
    if "round" in query and query["round"]:
        serialized_query["round"] = {
            "name": query["round"].name,
            "uuid": query["round"].uuid.hex,
        }
    if "proposal_states" in query:
        serialized_query["proposal_states"] = query["proposal_states"]
    serialized_query["include_reviewers"] = query.get("include_reviewers", False)
    serialized_query["send_to_me"] = query.get("send_to_me", False)
    if "additional_recipients" in query:
        serialized_query["additional_recipients"] = query["additional_recipients"]
    if "excluded_recipients" in query:
        serialized_query["excluded_recipients"] = query["excluded_recipients"]
    return serialized_query


class BroadcastMessageAttachmentSerializer(serializers.ModelSerializer):
    uploaded_by_full_name = serializers.ReadOnlyField(
        source="uploaded_by.full_name"
    )
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = models.BroadcastMessageAttachment
        fields = (
            "uuid",
            "filename",
            "size",
            "created",
            "uploaded_by_full_name",
            "file_url",
        )
        read_only_fields = ("uuid", "created", "uploaded_by_full_name", "file_url")

    def get_file_url(self, obj) -> str | None:
        request = self.context.get("request")
        if request and obj.file:
            return request.build_absolute_uri(obj.file.url)
        return None


class BroadcastMessageSerializer(
    RestrictedSerializerMixin, serializers.ModelSerializer
):
    author_full_name = serializers.ReadOnlyField(source="author.full_name")
    state = serializers.ReadOnlyField()
    emails = serializers.ReadOnlyField()
    attachments = BroadcastMessageAttachmentSerializer(many=True, read_only=True)

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
            "attachments",
        )

    def validate_query(self, query):
        serializer = QuerySerializer(data=query)
        serializer.is_valid()
        return serializer.validated_data

    def create(self, validated_data):
        current_user = self.context["request"].user
        validated_data["author"] = current_user
        # Pass request object for send_to_me functionality
        query_with_request = validated_data["query"].copy()
        query_with_request["_request"] = self.context["request"]
        validated_data["emails"] = utils.get_user_emails_for_query(
            query_with_request
        )
        validated_data["query"] = serialize_query(validated_data["query"])
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Pass request object for send_to_me functionality
        query_with_request = validated_data["query"].copy()
        query_with_request["_request"] = self.context["request"]
        validated_data["emails"] = utils.get_user_emails_for_query(
            query_with_request
        )
        validated_data["query"] = serialize_query(validated_data["query"])
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
