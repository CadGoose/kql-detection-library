"""Loading detections and shared constants."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Defaults are relative to the working directory (run the CLI from the repo root).
DEFAULT_DETECTIONS_DIR = Path("detections")
DEFAULT_ATTACK_FILE = Path("data") / "attack-techniques.json"

# Tactic names as used by Microsoft Sentinel analytics rules.
TACTICS: dict[str, str] = {
    "Reconnaissance": "reconnaissance",
    "ResourceDevelopment": "resource-development",
    "InitialAccess": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "PrivilegeEscalation": "privilege-escalation",
    "DefenseEvasion": "defense-evasion",
    "CredentialAccess": "credential-access",
    "Discovery": "discovery",
    "LateralMovement": "lateral-movement",
    "Collection": "collection",
    "CommandAndControl": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}

SEVERITIES = ("Informational", "Low", "Medium", "High")
STATUSES = ("stable", "experimental", "deprecated")
PLATFORMS = ("Sentinel", "DefenderXDR")
REQUIRED_FIELDS = (
    "id", "name", "description", "severity", "status", "platforms", "data_sources",
    "tactics", "techniques", "query_frequency", "query_period", "query",
    "false_positives", "tuning",
)


@dataclass
class Detection:
    path: Path
    data: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    @property
    def id(self) -> str:
        return str(self.data.get("id", ""))

    @property
    def folder(self) -> str:
        return self.path.parent.name


def load_detections(root: Path = DEFAULT_DETECTIONS_DIR) -> list[Detection]:
    """Load every *.yaml / *.yml file under root, sorted by path."""
    detections = []
    for path in sorted(list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            det = Detection(path, {})
            det.errors.append(f"YAML parse error: {exc}")
            detections.append(det)
            continue
        if not isinstance(data, dict):
            det = Detection(path, {})
            det.errors.append("top-level YAML must be a mapping")
            detections.append(det)
            continue
        detections.append(Detection(path, data))
    return detections


def load_attack(path: Path = DEFAULT_ATTACK_FILE) -> dict[str, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}
