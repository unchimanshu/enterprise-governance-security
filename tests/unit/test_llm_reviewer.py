import json
from unittest.mock import MagicMock

import pytest

from src.models import Finding, HIPAARule, Severity
from src.llm_reviewer import review_with_llm


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


def _mock_client(response_dict):
    client = MagicMock()
    msg = MagicMock()
    msg.content = json.dumps(response_dict)
    client.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=msg)])
    return client


def test_empty_diff_returns_empty_without_calling_openai(rules):
    client = MagicMock()
    result = review_with_llm("", rules, [], client)
    assert result == []
    client.chat.completions.create.assert_not_called()


def test_whitespace_only_diff_returns_empty(rules):
    client = MagicMock()
    result = review_with_llm("   \n  ", rules, [], client)
    assert result == []
    client.chat.completions.create.assert_not_called()


def test_valid_response_returns_correct_finding(rules):
    client = _mock_client({"findings": [{
        "rule_id": "HIPAA-001",
        "file_path": "auth.py",
        "line_number": 42,
        "code_snippet": "logging.info(patient_id)",
        "explanation": "PHI in log",
    }]})
    findings = review_with_llm("+ changed code", rules, [], client)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "HIPAA-001"
    assert f.file_path == "auth.py"
    assert f.line_number == 42
    assert f.source == "llm"
    assert f.severity == Severity.HIGH


def test_unknown_rule_id_in_response_skipped(rules):
    client = _mock_client({"findings": [{
        "rule_id": "HIPAA-999",
        "file_path": "auth.py",
        "line_number": 1,
        "code_snippet": "code",
        "explanation": "...",
    }]})
    findings = review_with_llm("+ changed", rules, [], client)
    assert findings == []


def test_malformed_json_returns_empty(rules):
    client = MagicMock()
    msg = MagicMock()
    msg.content = "this is not json at all"
    client.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=msg)])
    findings = review_with_llm("+ changed", rules, [], client)
    assert findings == []


def test_semgrep_findings_appear_in_prompt_to_avoid_duplicates(rules):
    semgrep_finding = Finding(
        rule_id="HIPAA-001",
        hipaa_reference="45 CFR §164.312(b)",
        category="Audit Controls",
        severity=Severity.HIGH,
        file_path="auth.py",
        line_number=10,
        code_snippet="logging.info(patient_id)",
        description="PHI in logs.",
        developer_message="Remove PHI from logs.",
        source="semgrep",
    )
    client = _mock_client({"findings": []})
    review_with_llm("+ changed", rules, [semgrep_finding], client)

    call_kwargs = client.chat.completions.create.call_args.kwargs
    user_msg = call_kwargs["messages"][1]["content"]
    assert "HIPAA-001" in user_msg
    assert "auth.py:10" in user_msg


def test_temperature_is_zero(rules):
    client = _mock_client({"findings": []})
    review_with_llm("+ changed", rules, [], client)
    call_kwargs = client.chat.completions.create.call_args.kwargs
    assert call_kwargs["temperature"] == 0


def test_no_semgrep_findings_shows_none_in_prompt(rules):
    client = _mock_client({"findings": []})
    review_with_llm("+ changed", rules, [], client)
    call_kwargs = client.chat.completions.create.call_args.kwargs
    user_msg = call_kwargs["messages"][1]["content"]
    assert "None" in user_msg
