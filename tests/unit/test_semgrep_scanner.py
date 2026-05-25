import json
from unittest.mock import MagicMock, patch

import pytest

from src.models import HIPAARule, Severity
from src.semgrep_scanner import run_semgrep


@pytest.fixture
def rules():
    return {
        "HIPAA-001": HIPAARule(
            rule_id="HIPAA-001",
            hipaa_reference="45 CFR §164.312(b)",
            category="Audit Controls",
            description="PHI in logs.",
            developer_message="Remove PHI from logs.",
            severity=Severity.HIGH,
            semgrep_rule_id="hipaa-phi-in-logs",
        )
    }


SEMGREP_HIT = {
    "results": [
        {
            "check_id": "semgrep_rules.hipaa.hipaa-phi-in-logs",
            "path": "/tmp/auth.py",
            "start": {"line": 10},
            "extra": {
                "severity": "ERROR",
                "lines": 'logging.info("ssn=%s", patient_id)',
            },
        }
    ]
}


def _mock_run(output):
    return MagicMock(stdout=json.dumps(output))


def test_empty_file_list_returns_empty_without_subprocess(rules):
    with patch("src.semgrep_scanner.subprocess.run") as mock:
        result = run_semgrep([], "semgrep_rules/", rules)
    assert result == []
    mock.assert_not_called()


def test_valid_output_produces_correct_finding(rules):
    with patch("src.semgrep_scanner.subprocess.run", return_value=_mock_run(SEMGREP_HIT)):
        findings = run_semgrep(["auth.py"], "semgrep_rules/", rules)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "HIPAA-001"
    assert f.line_number == 10
    assert f.source == "semgrep"
    assert f.file_path == "/tmp/auth.py"


def test_invalid_json_from_subprocess_returns_empty(rules):
    with patch("src.semgrep_scanner.subprocess.run", return_value=MagicMock(stdout="not-json")):
        findings = run_semgrep(["auth.py"], "semgrep_rules/", rules)
    assert findings == []


def test_unknown_semgrep_rule_id_skipped(rules):
    output = {
        "results": [{
            "check_id": "semgrep_rules.hipaa.unknown-rule",
            "path": "/tmp/auth.py",
            "start": {"line": 5},
            "extra": {"severity": "ERROR", "lines": "code"},
        }]
    }
    with patch("src.semgrep_scanner.subprocess.run", return_value=_mock_run(output)):
        findings = run_semgrep(["auth.py"], "semgrep_rules/", rules)
    assert findings == []


def test_severity_mapping_warning_becomes_medium(rules):
    output = {
        "results": [{
            "check_id": "semgrep_rules.hipaa.hipaa-phi-in-logs",
            "path": "/tmp/auth.py",
            "start": {"line": 5},
            "extra": {"severity": "WARNING", "lines": "code"},
        }]
    }
    with patch("src.semgrep_scanner.subprocess.run", return_value=_mock_run(output)):
        findings = run_semgrep(["auth.py"], "semgrep_rules/", rules)
    assert findings[0].severity == Severity.MEDIUM


def test_severity_mapping_info_becomes_low(rules):
    output = {
        "results": [{
            "check_id": "semgrep_rules.hipaa.hipaa-phi-in-logs",
            "path": "/tmp/auth.py",
            "start": {"line": 5},
            "extra": {"severity": "INFO", "lines": "code"},
        }]
    }
    with patch("src.semgrep_scanner.subprocess.run", return_value=_mock_run(output)):
        findings = run_semgrep(["auth.py"], "semgrep_rules/", rules)
    assert findings[0].severity == Severity.LOW


def test_code_snippet_stripped(rules):
    output = {
        "results": [{
            "check_id": "semgrep_rules.hipaa.hipaa-phi-in-logs",
            "path": "/tmp/auth.py",
            "start": {"line": 1},
            "extra": {"severity": "ERROR", "lines": "  logging.info(patient_id)  "},
        }]
    }
    with patch("src.semgrep_scanner.subprocess.run", return_value=_mock_run(output)):
        findings = run_semgrep(["auth.py"], "semgrep_rules/", rules)
    assert findings[0].code_snippet == "logging.info(patient_id)"
