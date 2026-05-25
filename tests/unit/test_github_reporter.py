from unittest.mock import MagicMock, patch

import pytest

from src.models import Finding, ReviewResult, Severity
from src.github_reporter import build_pr_comment, post_results


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


# --- build_pr_comment ---

def test_passed_comment_contains_checkmark():
    comment = build_pr_comment(_passed())
    assert "✅" in comment
    assert "Passed" in comment


def test_passed_comment_has_no_violation_content():
    comment = build_pr_comment(_passed())
    assert "HIPAA-001" not in comment
    assert "🚨" not in comment


def test_failed_comment_contains_alert_emoji():
    comment = build_pr_comment(_failed())
    assert "🚨" in comment


def test_failed_comment_contains_rule_id():
    comment = build_pr_comment(_failed())
    assert "HIPAA-001" in comment


def test_failed_comment_contains_file_and_line():
    comment = build_pr_comment(_failed())
    assert "auth.py" in comment
    assert "42" in comment


def test_failed_comment_contains_hipaa_reference():
    comment = build_pr_comment(_failed())
    assert "45 CFR §164.312(b)" in comment


def test_failed_comment_contains_developer_message():
    comment = build_pr_comment(_failed())
    assert "Remove PHI from logs." in comment


def test_failed_comment_contains_source():
    comment = build_pr_comment(_failed())
    assert "semgrep" in comment


# --- post_results ---

def _setup_github_mock():
    mock_repo = MagicMock()
    mock_pr = MagicMock()
    mock_commit = MagicMock()
    mock_pr.head.sha = "abc123"
    mock_repo.get_pull.return_value = mock_pr
    mock_repo.get_commit.return_value = mock_commit
    return mock_repo, mock_pr, mock_commit


def test_post_results_success_sets_correct_status():
    mock_repo, mock_pr, mock_commit = _setup_github_mock()
    with patch("src.github_reporter.Github") as mock_github:
        mock_github.return_value.get_repo.return_value = mock_repo
        post_results(_passed(), "org/repo", 1, "token")

    mock_commit.create_status.assert_called_once_with(
        state="success",
        description="No HIPAA violations found.",
        context="hipaa-security-review",
        target_url="",
    )


def test_post_results_failure_sets_correct_status():
    mock_repo, mock_pr, mock_commit = _setup_github_mock()
    with patch("src.github_reporter.Github") as mock_github:
        mock_github.return_value.get_repo.return_value = mock_repo
        post_results(_failed(), "org/repo", 1, "token")

    mock_commit.create_status.assert_called_once_with(
        state="failure",
        description="1 HIPAA violation(s) detected. Merge blocked.",
        context="hipaa-security-review",
        target_url="",
    )


def test_post_results_always_posts_pr_comment():
    mock_repo, mock_pr, mock_commit = _setup_github_mock()
    with patch("src.github_reporter.Github") as mock_github:
        mock_github.return_value.get_repo.return_value = mock_repo
        post_results(_passed(), "org/repo", 1, "token")

    mock_pr.create_issue_comment.assert_called_once()
