"""Schema and content validation for detection YAML files."""

from __future__ import annotations

import re
from collections import Counter

from .kql import lint_query
from .model import PLATFORMS, REQUIRED_FIELDS, SEVERITIES, STATUSES, TACTICS, Detection

ID_RE = re.compile(r"^KDL-\d{4}$")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DURATION_RE = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")

MIN_FREQUENCY_MIN = 5
MAX_PERIOD_MIN = 14 * 24 * 60  # Sentinel scheduled rules: queryPeriod <= 14 days


def duration_minutes(value: str) -> int | None:
    """Parse the ISO-8601 subset Sentinel uses (P#D, PT#H, PT#M, combos)."""
    m = DURATION_RE.match(value or "")
    if not m or value in ("P", "PT"):
        return None
    days, hours, minutes = (int(g) if g else 0 for g in m.groups())
    total = days * 1440 + hours * 60 + minutes
    return total or None


def validate_detection(det: Detection, attack: dict[str, str]) -> list[str]:
    errors = list(det.errors)
    d = det.data
    if not d:
        return errors

    for key in REQUIRED_FIELDS:
        if key not in d or d[key] in (None, "", []):
            errors.append(f"missing required field '{key}'")

    did = str(d.get("id", ""))
    if did and not ID_RE.match(did):
        errors.append(f"id '{did}' must match KDL-0000")
    if did and not det.path.name.startswith(did + "-"):
        errors.append(f"filename must start with '{did}-'")

    if d.get("severity") and d["severity"] not in SEVERITIES:
        errors.append(f"severity must be one of {SEVERITIES}")
    if d.get("status") and d["status"] not in STATUSES:
        errors.append(f"status must be one of {STATUSES}")

    for p in d.get("platforms") or []:
        if p not in PLATFORMS:
            errors.append(f"unknown platform '{p}' (allowed: {PLATFORMS})")

    tactics = d.get("tactics") or []
    for t in tactics:
        if t not in TACTICS:
            errors.append(f"unknown tactic '{t}'")
    folder_tactics = {TACTICS[t] for t in tactics if t in TACTICS}
    if tactics and det.folder not in folder_tactics:
        errors.append(f"file lives in '{det.folder}/' but none of its tactics map there ({sorted(folder_tactics)})")

    for tech in d.get("techniques") or []:
        if not TECH_RE.match(str(tech)):
            errors.append(f"technique '{tech}' is not a valid ATT&CK ID")
        elif tech not in attack:
            errors.append(f"technique '{tech}' not in data/attack-techniques.json")

    freq = duration_minutes(str(d.get("query_frequency", "")))
    period = duration_minutes(str(d.get("query_period", "")))
    if d.get("query_frequency") and freq is None:
        errors.append("query_frequency must be ISO-8601 like PT1H / PT15M / P1D")
    if d.get("query_period") and period is None:
        errors.append("query_period must be ISO-8601 like PT1H / P1D / P14D")
    if freq is not None and freq < MIN_FREQUENCY_MIN:
        errors.append("query_frequency must be at least PT5M")
    if period is not None and period > MAX_PERIOD_MIN:
        errors.append("query_period cannot exceed P14D (Sentinel limit)")
    if freq is not None and period is not None and period < freq:
        errors.append("query_period must be >= query_frequency or events will be missed")

    query = str(d.get("query") or "")
    for problem in lint_query(query):
        errors.append(f"query: {problem}")

    for i, em in enumerate(d.get("entity_mappings") or []):
        for k in ("entity", "field", "column"):
            if k not in em:
                errors.append(f"entity_mappings[{i}] missing '{k}'")
        col = em.get("column")
        if col and not re.search(rf"\b{re.escape(col)}\b", query):
            errors.append(f"entity_mappings[{i}] column '{col}' does not appear in the query")

    for key in ("false_positives", "tuning", "references"):
        if key in d and d[key] is not None and not isinstance(d[key], list):
            errors.append(f"'{key}' must be a list")
    return errors


def validate_all(detections: list[Detection], attack: dict[str, str]) -> dict[str, list[str]]:
    """Return {path: [errors]} for every file that has problems."""
    results: dict[str, list[str]] = {}
    ids = Counter(det.id for det in detections if det.id)
    names = Counter(str(det.get("name", "")).lower() for det in detections)
    for det in detections:
        errs = validate_detection(det, attack)
        if det.id and ids[det.id] > 1:
            errs.append(f"duplicate id '{det.id}'")
        if det.get("name") and names[str(det.get("name")).lower()] > 1:
            errs.append("duplicate detection name")
        if errs:
            results[str(det.path)] = errs
    return results
