import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from src.models import ReviewResult, Severity

SEVERITY_LABEL = {
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
}


def send_violation_alert(
    result: ReviewResult,
    repo_name: str,
    pr_number: int,
    pr_url: str,
    from_email: str,
    to_email: str,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
) -> None:
    if result.passed:
        return

    subject = f"[HIPAA Security Alert] {result.total_violations} violation(s) in {repo_name} PR #{pr_number}"
    body = _build_email_body(result, repo_name, pr_number, pr_url)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, to_email, msg.as_string())


def _build_email_body(result: ReviewResult, repo_name: str, pr_number: int, pr_url: str) -> str:
    lines = [
        f"HIPAA Security Review — {result.total_violations} Violation(s) Detected",
        f"Repository: {repo_name}",
        f"Pull Request: #{pr_number}",
        f"PR URL: {pr_url}",
        f"Summary: {result.summary}",
        "",
        "VIOLATIONS",
        "=" * 60,
    ]

    for finding in result.findings:
        lines += [
            f"",
            f"Rule:      {finding.rule_id}",
            f"Reference: {finding.hipaa_reference}",
            f"Severity:  {SEVERITY_LABEL[finding.severity]}",
            f"File:      {finding.file_path}:{finding.line_number}",
            f"Code:      {finding.code_snippet}",
            f"Issue:     {finding.description}",
            f"Fix:       {finding.developer_message}",
            "-" * 60,
        ]

    lines += [
        "",
        "This merge has been blocked. The developer must resolve all violations before merging.",
        "Contact the developer or review the PR for details.",
    ]

    return "\n".join(lines)
