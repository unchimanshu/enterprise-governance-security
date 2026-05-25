from __future__ import annotations

import json
import subprocess
from pathlib import Path

from src.models import Finding, HIPAARule, Severity
from src.rule_loader import get_rule_by_semgrep_id


def run_semgrep(target_files: list[str], rules_path: str | Path, rules: dict[str, HIPAARule]) -> list[Finding]:
    if not target_files:
        return []

    cmd = [
        "semgrep",
        "--config", str(rules_path),
        "--json",
        "--quiet",
        *target_files,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for match in output.get("results", []):
        semgrep_rule_id = match["check_id"].split(".")[-1]
        rule = get_rule_by_semgrep_id(rules, semgrep_rule_id)
        if rule is None:
            continue

        severity_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
        semgrep_severity = match.get("extra", {}).get("severity", "ERROR")

        findings.append(Finding(
            rule_id=rule.rule_id,
            hipaa_reference=rule.hipaa_reference,
            category=rule.category,
            severity=severity_map.get(semgrep_severity, rule.severity),
            file_path=match["path"],
            line_number=match["start"]["line"],
            code_snippet=match["extra"].get("lines", "").strip(),
            description=rule.description,
            developer_message=rule.developer_message,
            source="semgrep",
        ))

    return findings
