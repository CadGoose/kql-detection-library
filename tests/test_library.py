import json
import textwrap
from pathlib import Path

import pytest

from kqldl.cli import main
from kqldl.docs import build_html, coverage
from kqldl.export_arm import build_template, rule_guid
from kqldl.kql import lint_query, strip_strings_and_comments
from kqldl.model import Detection, load_attack, load_detections
from kqldl.validate import duration_minutes, validate_all, validate_detection

ROOT = Path(__file__).resolve().parent.parent
ATTACK = load_attack(ROOT / "data" / "attack-techniques.json")


@pytest.fixture(scope="module")
def detections():
    return load_detections(ROOT / "detections")


def test_repository_detections_are_valid(detections):
    assert len(detections) >= 25
    assert validate_all(detections, ATTACK) == {}


def test_ids_are_unique_and_sequential(detections):
    ids = sorted(d.id for d in detections)
    assert len(ids) == len(set(ids))


GOOD = {
    "id": "KDL-9999", "name": "Test", "description": "d", "severity": "High", "status": "stable",
    "platforms": ["Sentinel"], "data_sources": ["SigninLogs"], "tactics": ["InitialAccess"],
    "techniques": ["T1078.004"], "query_frequency": "PT1H", "query_period": "PT1H",
    "query": "SigninLogs\n| where TimeGenerated > ago(1h)\n| project UserPrincipalName",
    "false_positives": ["x"], "tuning": ["y"],
    "entity_mappings": [{"entity": "Account", "field": "FullName", "column": "UserPrincipalName"}],
}


def _det(**overrides):
    data = {**GOOD, **overrides}
    return Detection(Path("detections/initial-access/KDL-9999-test.yaml"), data)


def test_good_detection_passes():
    assert validate_detection(_det(), ATTACK) == []


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"id": "KDL-12"}, "must match"),
        ({"severity": "Critical"}, "severity"),
        ({"tactics": ["Initial Access"]}, "unknown tactic"),
        ({"tactics": ["Impact"]}, "none of its tactics map there"),
        ({"techniques": ["T9999"]}, "not in data/attack-techniques.json"),
        ({"techniques": ["1078"]}, "not a valid ATT&CK ID"),
        ({"query_period": "P30D"}, "cannot exceed P14D"),
        ({"query_frequency": "PT1M"}, "at least PT5M"),
        ({"query_frequency": "P1D", "query_period": "PT1H"}, "must be >= query_frequency"),
        ({"query": "SigninLogs | project UserPrincipalName"}, "no time filter"),
        ({"query": "SigninLogs\n| where TimeGenerated > ago(1h) and (x == 1\n| project UserPrincipalName"}, "unclosed '('"),
        ({"platforms": ["Splunk"]}, "unknown platform"),
        ({"entity_mappings": [{"entity": "IP", "field": "Address", "column": "IPAddress"}]}, "does not appear"),
        ({"tuning": None}, "missing required field 'tuning'"),
    ],
)
def test_validator_catches_problems(overrides, expected):
    errors = validate_detection(_det(**overrides), ATTACK)
    assert any(expected in e for e in errors), errors


def test_duplicate_ids_flagged():
    a = _det()
    b = Detection(Path("detections/initial-access/KDL-9999-other.yaml"), {**GOOD, "name": "Other"})
    results = validate_all([a, b], ATTACK)
    assert any("duplicate id" in e for errs in results.values() for e in errs)


def test_duration_parser():
    assert duration_minutes("PT15M") == 15
    assert duration_minutes("PT1H") == 60
    assert duration_minutes("P1D") == 1440
    assert duration_minutes("P1DT2H") == 1560
    assert duration_minutes("1h") is None
    assert duration_minutes("PT") is None


def test_lint_ignores_brackets_inside_strings():
    q = textwrap.dedent(r'''
        T | where TimeGenerated > ago(1h)
        | extend a = extract(@"(https?://[^\s'""]+)", 1, x)   // a ( comment
        | extend b = "unbalanced ( in string", c = 'also ]'
    ''')
    assert lint_query(q) == []


def test_lint_flags_unterminated_string():
    assert any("unterminated" in p for p in lint_query('T | where TimeGenerated > ago(1h) | where x == "abc'))


def test_strip_preserves_length():
    q = 'T | where a == "x(y" // z)'
    code, problems = strip_strings_and_comments(q)
    assert len(code) == len(q) and problems == []


def test_arm_export_shape(detections):
    template = build_template(detections)
    rules = template["resources"]
    assert len(rules) == sum(1 for d in detections if "Sentinel" in d["platforms"])
    names = [r["name"] for r in rules]
    assert len(names) == len(set(names))
    for r in rules:
        p = r["properties"]
        assert r["kind"] == "Scheduled"
        assert all("." not in t for t in p["techniques"])
        assert p["queryFrequency"].startswith("P")
        assert p["displayName"].startswith("[KDL-")
    json.dumps(template)


def test_rule_guid_is_stable():
    assert rule_guid("KDL-0001") == rule_guid("KDL-0001")
    assert rule_guid("KDL-0001") != rule_guid("KDL-0002")


def test_docs_contain_every_detection(detections):
    page = build_html(detections, ATTACK)
    for d in detections:
        assert f'id="{d.id}"' in page
    assert "<script>" in page and "ATT&amp;CK" in page
    cov = coverage(detections)
    assert set(cov) <= {t for d in detections for t in d["tactics"]}


def test_cli_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    assert main(["validate"]) == 0
    out = tmp_path / "rules.json"
    assert main(["export-arm", "-o", str(out)]) == 0
    assert json.loads(out.read_text())["resources"]
    assert main(["build-docs", "-o", str(tmp_path / "site")]) == 0
    assert (tmp_path / "site" / "index.html").exists()


def test_humanizers():
    from kqldl.docs import humanize_duration, humanize_tactic
    assert humanize_tactic("CommandAndControl") == "Command and Control"
    assert humanize_tactic("InitialAccess") == "Initial Access"
    assert humanize_duration("PT15M") == "15m"
    assert humanize_duration("P14D") == "14d"
