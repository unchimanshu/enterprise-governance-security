import json
import pytest
from src.models import Severity
from src.rule_loader import get_rule_by_semgrep_id, load_rules


HIPAA_RULE = {
    "rule_id": "HIPAA-001",
    "hipaa_reference": "45 CFR §164.312(b)",
    "category": "Audit Controls",
    "description": "PHI in logs.",
    "developer_message": "Remove PHI from logs.",
    "severity": "high",
    "semgrep_rule_id": "hipaa-phi-in-logs",
}

SEC_RULE = {
    "rule_id": "SEC-001",
    "hipaa_reference": "N/A",
    "category": "Secrets",
    "description": "AWS key.",
    "developer_message": "Remove it.",
    "severity": "high",
    "semgrep_rule_id": "sec-aws-access-key-id",
}


def _write_json(path, rules_list):
    path.write_text(json.dumps({"framework": "test", "version": "1", "description": "test", "rules": rules_list}))


def test_load_rules_from_single_file(tmp_path):
    f = tmp_path / "rules.json"
    _write_json(f, [HIPAA_RULE])
    rules = load_rules(f)
    assert "HIPAA-001" in rules
    assert rules["HIPAA-001"].severity == Severity.HIGH


def test_load_rules_from_directory_merges_all(tmp_path):
    _write_json(tmp_path / "hipaa.json", [HIPAA_RULE])
    _write_json(tmp_path / "secrets.json", [SEC_RULE])
    rules = load_rules(tmp_path)
    assert "HIPAA-001" in rules
    assert "SEC-001" in rules


def test_load_rules_preserves_all_fields(tmp_path):
    f = tmp_path / "rules.json"
    _write_json(f, [HIPAA_RULE])
    rule = load_rules(f)["HIPAA-001"]
    assert rule.hipaa_reference == "45 CFR §164.312(b)"
    assert rule.category == "Audit Controls"
    assert rule.semgrep_rule_id == "hipaa-phi-in-logs"
    assert rule.developer_message == "Remove PHI from logs."


def test_get_rule_by_semgrep_id_found(tmp_path):
    f = tmp_path / "rules.json"
    _write_json(f, [HIPAA_RULE])
    rules = load_rules(f)
    rule = get_rule_by_semgrep_id(rules, "hipaa-phi-in-logs")
    assert rule is not None
    assert rule.rule_id == "HIPAA-001"


def test_get_rule_by_semgrep_id_not_found(tmp_path):
    f = tmp_path / "rules.json"
    _write_json(f, [HIPAA_RULE])
    rules = load_rules(f)
    assert get_rule_by_semgrep_id(rules, "nonexistent-rule") is None
