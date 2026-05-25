from src.models import Finding


def merge_findings(semgrep_findings: list[Finding], llm_findings: list[Finding]) -> list[Finding]:
    merged: list[Finding] = list(semgrep_findings)
    seen: set[tuple] = {_finding_key(f) for f in semgrep_findings}

    for finding in llm_findings:
        key = _finding_key(finding)
        if key not in seen:
            merged.append(finding)
            seen.add(key)

    merged.sort(key=lambda f: (f.file_path, f.line_number))
    return merged


def _finding_key(finding: Finding) -> tuple:
    return (finding.rule_id, finding.file_path, finding.line_number)
