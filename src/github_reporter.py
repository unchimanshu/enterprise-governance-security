import os
from github import Github
from github.PullRequest import PullRequest
from src.models import Finding, ReviewResult, Severity

SEVERITY_EMOJI = {
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}


def build_pr_comment(result: ReviewResult) -> str:
    if result.passed:
        return (
            "## ✅ HIPAA Security Review — Passed\n\n"
            "No HIPAA policy violations detected in this pull request."
        )

    lines = [
        "## 🚨 HIPAA Security Review — Failed\n",
        f"**{result.total_violations} violation(s) found.** This PR is blocked from merging until all violations are resolved.\n",
        "---\n",
    ]

    for finding in result.findings:
        emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")
        lines.append(f"### {emoji} `{finding.rule_id}` — {finding.category}")
        lines.append(f"**File:** `{finding.file_path}` — Line {finding.line_number}")
        lines.append(f"**HIPAA Reference:** {finding.hipaa_reference}")
        lines.append(f"**Severity:** {finding.severity.value.upper()}")
        lines.append(f"**Detected by:** {finding.source}")
        lines.append(f"\n```python\n{finding.code_snippet}\n```")
        lines.append(f"\n**What went wrong:** {finding.description}")
        lines.append(f"\n**How to fix:** {finding.developer_message}\n")
        lines.append("---\n")

    lines.append(
        "_This review is automated by the Enterprise Security Reviewer. "
        "Contact your Security Admin if you believe this is a false positive._"
    )

    return "\n".join(lines)


def post_results(result: ReviewResult, repo_name: str, pr_number: int, github_token: str) -> None:
    gh = Github(github_token)
    repo = gh.get_repo(repo_name)
    pr: PullRequest = repo.get_pull(pr_number)

    comment_body = build_pr_comment(result)
    pr.create_issue_comment(comment_body)

    commit = repo.get_commit(pr.head.sha)
    state = "success" if result.passed else "failure"
    description = (
        "No HIPAA violations found."
        if result.passed
        else f"{result.total_violations} HIPAA violation(s) detected. Merge blocked."
    )

    commit.create_status(
        state=state,
        description=description,
        context="hipaa-security-review",
        target_url="",
    )
