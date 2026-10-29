from django.db import transaction

from . import models, serializers


class FlowImportError(ValueError):
    pass


def import_flows(document, dry_run=False) -> list:
    """Create or update flows from {"flows": [{key, name, description,
    steps}]}, by key. Checked by the same rules as the API, so a file cannot
    save what the API would refuse. All or nothing.

    Returns [(key, "created" | "updated" | "unchanged")].
    """
    if not isinstance(document, dict) or not isinstance(document.get("flows"), list):
        raise FlowImportError("Expected a mapping with a 'flows' list.")
    results = []
    with transaction.atomic():
        for index, item in enumerate(document["flows"]):
            if not isinstance(item, dict) or not item.get("key"):
                raise FlowImportError(f"Flow {index + 1} has no key.")
            data = {
                "key": item["key"],
                "name": item.get("name") or item["key"],
                "description": item.get("description", ""),
                "steps": item.get("steps"),
            }
            flow = models.FormFlow.objects.filter(key=data["key"]).first()
            serializer = serializers.FormFlowSerializer(flow, data=data)
            if not serializer.is_valid():
                raise FlowImportError(f"Flow {data['key']!r}: {serializer.errors}")
            if flow is None:
                action = "created"
            elif all(
                getattr(flow, field) == serializer.validated_data[field]
                for field in ("name", "description", "steps")
            ):
                action = "unchanged"
            else:
                action = "updated"
            if action != "unchanged":
                serializer.save()
            results.append((data["key"], action))
        if dry_run:
            transaction.set_rollback(True)
    return results


def export_flows(keys=None) -> dict:
    flows = models.FormFlow.objects.order_by("key")
    if keys:
        flows = flows.filter(key__in=keys)
    return {
        "flows": [
            {
                "key": flow.key,
                "name": flow.name,
                "description": flow.description,
                "steps": flow.steps,
            }
            for flow in flows
        ]
    }
