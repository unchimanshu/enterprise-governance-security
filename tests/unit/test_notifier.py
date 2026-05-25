from unittest.mock import MagicMock, patch

from src.models import Finding, ReviewResult, Severity
from src.notifier import _build_email_body, send_violation_alert


def _finding():
    return Finding(
        rule_id="HIPAA-001",
        hipaa_reference="45 CFR §164.312(b)",
        category="Audit Controls",
        severity=Severity.HIGH,
        file_path="auth.py",
        line_number=42,
        code_snippet="logging.info(patient_id)",
        description="PHI in logs.",
        developer_message="Remove PHI from logs.",
        source="semgrep",
    )


def _passed():
    return ReviewResult(findings=[], passed=True, total_violations=0, summary="No violations.")


def _failed():
    return ReviewResult(
        findings=[_finding()],
        passed=False,
        total_violations=1,
        summary="1 violation(s) found.",
    )


SMTP_KWARGS = dict(
    repo_name="org/repo",
    pr_number=7,
    pr_url="https://github.com/org/repo/pull/7",
    from_email="sec@org.com",
    to_email="admin@org.com",
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_user="user",
    smtp_password="pass",
)


def test_no_email_sent_when_passed():
    with patch("src.notifier.smtplib.SMTP") as mock_smtp:
        send_violation_alert(result=_passed(), **SMTP_KWARGS)
    mock_smtp.assert_not_called()


def test_email_sent_when_violations_found():
    with patch("src.notifier.smtplib.SMTP") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        send_violation_alert(result=_failed(), **SMTP_KWARGS)
    mock_server.sendmail.assert_called_once()


def test_email_from_and_to_addresses_correct():
    with patch("src.notifier.smtplib.SMTP") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        send_violation_alert(result=_failed(), **SMTP_KWARGS)

    args = mock_server.sendmail.call_args[0]
    assert args[0] == "sec@org.com"
    assert args[1] == "admin@org.com"


def test_email_uses_starttls():
    with patch("src.notifier.smtplib.SMTP") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        send_violation_alert(result=_failed(), **SMTP_KWARGS)
    mock_server.starttls.assert_called_once()


def test_email_body_contains_rule_id():
    body = _build_email_body(_failed(), "org/repo", 7, "https://github.com/org/repo/pull/7")
    assert "HIPAA-001" in body


def test_email_body_contains_file_and_line():
    body = _build_email_body(_failed(), "org/repo", 7, "https://github.com/org/repo/pull/7")
    assert "auth.py:42" in body


def test_email_body_contains_severity():
    body = _build_email_body(_failed(), "org/repo", 7, "https://github.com/org/repo/pull/7")
    assert "HIGH" in body


def test_email_body_contains_developer_message():
    body = _build_email_body(_failed(), "org/repo", 7, "https://github.com/org/repo/pull/7")
    assert "Remove PHI from logs." in body


def test_email_body_contains_pr_url():
    body = _build_email_body(_failed(), "org/repo", 7, "https://github.com/org/repo/pull/7")
    assert "https://github.com/org/repo/pull/7" in body
