import os
import sys
import tempfile
from pathlib import Path

import requests
from dotenv import load_dotenv
from openai import OpenAI

from src.findings_merger import merge_findings
from src.github_reporter import post_results
from src.llm_reviewer import review_with_llm
from src.models import ReviewResult
from src.notifier import send_violation_alert
from src.rule_loader import load_rules
from src.semgrep_scanner import run_semgrep

load_dotenv()

POLICIES_DIR = Path(__file__).parent / "policies"
SEMGREP_RULES_DIR = Path(__file__).parent / "semgrep_rules"


def fetch_pr_diff(repo_name: str, pr_number: int, github_token: str) -> str:
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.text


def extract_changed_python_files(github_token: str, repo_name: str, pr_number: int) -> list[str]:
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files"
    headers = {"Authorization": f"Bearer {github_token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    files = response.json()
    return [
        f["filename"]
        for f in files
        if f["filename"].endswith(".py") and f["status"] != "removed"
    ]


def write_changed_files_locally(
    changed_files: list[str],
    repo_name: str,
    pr_number: int,
    github_token: str,
    tmp_dir: str,
) -> list[str]:
    local_paths: list[str] = []
    headers = {"Authorization": f"Bearer {github_token}"}

    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files"
    response = requests.get(url, headers=headers, timeout=30)
    file_map = {f["filename"]: f for f in response.json()}

    for file_path in changed_files:
        file_info = file_map.get(file_path)
        if not file_info or not file_info.get("raw_url"):
            continue

        content_response = requests.get(
            file_info["raw_url"], headers=headers, timeout=30
        )
        if content_response.status_code != 200:
            continue

        local_path = Path(tmp_dir) / file_path
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(content_response.text)
        local_paths.append(str(local_path))

    return local_paths


def build_summary(finding_count: int) -> str:
    if finding_count == 0:
        return "No HIPAA violations detected."
    return (
        f"{finding_count} HIPAA violation(s) found across changed files. "
        "Merge is blocked until all violations are resolved."
    )


def main() -> None:
    github_token = os.environ["GITHUB_TOKEN"]
    repo_name = os.environ["GITHUB_REPOSITORY"]
    pr_number = int(os.environ["GITHUB_PR_NUMBER"])
    openai_api_key = os.environ["OPENAI_API_KEY"]

    alert_from = os.getenv("ALERT_EMAIL_FROM", "")
    alert_to = os.getenv("ALERT_EMAIL_TO", "")
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")

    rules = load_rules(POLICIES_DIR)
    openai_client = OpenAI(api_key=openai_api_key)

    print(f"Fetching PR #{pr_number} diff from {repo_name}...")
    diff = fetch_pr_diff(repo_name, pr_number, github_token)

    changed_python_files = extract_changed_python_files(github_token, repo_name, pr_number)
    print(f"Changed Python files: {changed_python_files}")

    semgrep_findings = []
    if changed_python_files:
        with tempfile.TemporaryDirectory() as tmp_dir:
            local_files = write_changed_files_locally(
                changed_python_files, repo_name, pr_number, github_token, tmp_dir
            )
            print(f"Running Semgrep on {len(local_files)} file(s)...")
            semgrep_findings = run_semgrep(local_files, SEMGREP_RULES_DIR, rules)
            for f in semgrep_findings:
                f.file_path = f.file_path.replace(tmp_dir + "/", "")

    print(f"Semgrep found {len(semgrep_findings)} finding(s). Running LLM contextual review...")
    llm_findings = review_with_llm(diff, rules, semgrep_findings, openai_client)

    all_findings = merge_findings(semgrep_findings, llm_findings)
    passed = len(all_findings) == 0

    result = ReviewResult(
        findings=all_findings,
        passed=passed,
        total_violations=len(all_findings),
        summary=build_summary(len(all_findings)),
    )

    print(f"Posting results to PR #{pr_number}...")
    pr_url = f"https://github.com/{repo_name}/pull/{pr_number}"
    post_results(result, repo_name, pr_number, github_token)

    if not passed and all([alert_from, alert_to, smtp_host, smtp_user, smtp_password]):
        print(f"Sending violation alert email to {alert_to}...")
        send_violation_alert(
            result=result,
            repo_name=repo_name,
            pr_number=pr_number,
            pr_url=pr_url,
            from_email=alert_from,
            to_email=alert_to,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
        )

    print(result.summary)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
