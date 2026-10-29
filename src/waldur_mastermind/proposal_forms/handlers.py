"""Connects this app's fields onto upstream serializers."""

from waldur_core.core.signals import pre_serializer_fields
from waldur_mastermind.proposal import serializers as proposal_serializers

from . import serializers

# pre_serializer_fields is sent for the exact serializer class, so a subclass
# needs its own connection.
for call_serializer in (
    proposal_serializers.PublicCallSerializer,
    proposal_serializers.ProtectedCallSerializer,
):
    pre_serializer_fields.connect(
        sender=call_serializer,
        receiver=serializers.add_form_flow_to_call,
        dispatch_uid=f"proposal_forms.add_form_flow_to_{call_serializer.__name__}",
    )
