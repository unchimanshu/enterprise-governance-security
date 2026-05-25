"""
Threat intelligence pipeline: CISA KEV → stack matching → policy proposals.
"""
from __future__ import annotations

import json
import re
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import urllib.request

_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_REPO_ROOT = Path(__file__).parent.parent


def scan_stack() -> list[str]:
    """Return package names from requirements.txt."""
    packages: set[str] = set()
    req_file = _REPO_ROOT / "requirements.txt"
    if req_file.exists():
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name = re.split(r"[>=<!;~\[\s]", line)[0].strip().lower()
                if name:
                    packages.add(name)
    return sorted(packages)


def fetch_cisa_kev(timeout: int = 15) -> list[dict]:
    """Fetch entries from the CISA Known Exploited Vulnerabilities catalog."""
    with urllib.request.urlopen(_CISA_KEV_URL, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data.get("vulnerabilities", [])


def match_against_stack(kev_entries: list[dict], stack_packages: list[str]) -> list[dict]:
    """Return KEV entries whose product name fuzzy-matches a stack package."""
    matches: list[dict] = []
    pkg_set = {p.lower() for p in stack_packages}
    for entry in kev_entries:
        product = entry.get("product", "").lower()
        vendor = entry.get("vendorProject", "").lower()
        for pkg in pkg_set:
            if pkg in product or product in pkg or pkg in vendor:
                matches.append({**entry, "_matched_package": pkg})
                break
    return matches


def generate_proposed_rule(incident_data: dict, client, rule_id: str) -> dict:
    """Call GPT-4o to generate a proposed enforcement rule for a KEV entry."""
    prompt = (
        f"CVE: {incident_data.get('cveID', 'N/A')}\n"
        f"Product: {incident_data.get('product', 'N/A')}\n"
        f"Vulnerability: {incident_data.get('vulnerabilityName', 'N/A')}\n"
        f"Description: {incident_data.get('shortDescription', 'N/A')}\n\n"
        "Generate a single code-level enforcement rule a static analysis tool could check to detect "
        "or warn about this vulnerable dependency. Return JSON with exactly these keys: "
        f"rule_id (use '{rule_id}'), category (string), severity (must be 'medium'), "
        "description (1-2 sentences about what it checks), "
        "developer_message (1-2 sentences, actionable fix guidance)."
    )
    response = client.chat.completions.create(
        model="gpt-4o",
        response_format={"type": "json_object"},
        temperature=0,
        messages=[
            {"role": "system", "content": "You are a compliance rule generation engine. Output only valid JSON."},
            {"role": "user", "content": prompt},
        ],
    )
    rule = json.loads(response.choices[0].message.content)
    rule.setdefault("hipaa_reference", "N/A")
    rule.setdefault("semgrep_rule_id", None)
    rule["severity"] = "medium"
    return rule


def send_incident_alert(
    new_incidents: list[dict],
    to_email: str,
    from_email: str,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
) -> None:
    """Email admin when new threat intelligence incidents are found matching the stack."""
    if not new_incidents:
        return

    count = len(new_incidents)
    subject = f"[PolicyGuard] {count} new threat alert{'s' if count != 1 else ''} require your review"

    lines = [
        f"PolicyGuard has identified {count} new public CVE(s) affecting your tech stack.",
        "",
        "These incidents have been automatically translated into proposed policy rules.",
        "Log in to PolicyGuard → Threat Intelligence to approve or reject each rule.",
        "",
        "INCIDENTS DETECTED",
        "=" * 60,
    ]
    for inc in new_incidents:
        lines += [
            "",
            f"CVE:      {inc.get('cve_id', 'N/A')}",
            f"Package:  {inc.get('affected_package', 'N/A')}",
            f"Title:    {inc.get('title', 'N/A')}",
            f"Severity: {inc.get('severity', 'N/A').upper()}",
            "-" * 60,
        ]

    lines += ["", "Action required: Review proposed rules in PolicyGuard."]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.attach(MIMEText("\n".join(lines), "plain"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, to_email, msg.as_string())
