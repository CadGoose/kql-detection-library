"""Export detections as a Microsoft Sentinel analytics-rule ARM template."""

from __future__ import annotations

import uuid
from typing import Any

from .model import Detection

# Stable namespace so a detection always maps to the same rule GUID (idempotent redeploys).
_NAMESPACE = uuid.UUID("6f1c4c1e-8a4d-4e0c-9a59-6b0c1f6e2b10")
API_VERSION = "2023-02-01"


def rule_guid(detection_id: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, detection_id))


def _entity_mappings(det: Detection) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for em in det.get("entity_mappings") or []:
        grouped.setdefault(em["entity"], []).append(
            {"identifier": em["field"], "columnName": em["column"]}
        )
    return [{"entityType": k, "fieldMappings": v} for k, v in grouped.items()]


def detection_to_rule(det: Detection, enabled: bool = True) -> dict[str, Any]:
    techniques = sorted({t.split(".")[0] for t in det["techniques"]})
    sub_techniques = sorted({t for t in det["techniques"] if "." in t})
    props: dict[str, Any] = {
        "displayName": f"[{det.id}] {det['name']}",
        "description": " ".join(str(det["description"]).split()),
        "severity": det["severity"],
        "enabled": enabled,
        "query": str(det["query"]).rstrip() + "\n",
        "queryFrequency": det["query_frequency"],
        "queryPeriod": det["query_period"],
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": list(det["tactics"]),
        "techniques": techniques,
        "subTechniques": sub_techniques,
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
            },
        },
    }
    mappings = _entity_mappings(det)
    if mappings:
        props["entityMappings"] = mappings
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": API_VERSION,
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{rule_guid(det.id)}')]",
        "kind": "Scheduled",
        "properties": props,
    }


def build_template(detections: list[Detection], enabled: bool = True) -> dict[str, Any]:
    rules = [
        detection_to_rule(d, enabled)
        for d in detections
        if "Sentinel" in (d.get("platforms") or []) and d.get("status") != "deprecated"
    ]
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {"description": "Name of the Log Analytics workspace that has Microsoft Sentinel enabled."},
            }
        },
        "resources": rules,
    }
