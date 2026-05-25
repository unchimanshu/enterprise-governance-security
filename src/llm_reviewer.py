import json
from openai import OpenAI
from src.models import Finding, HIPAARule, Severity

SYSTEM_PROMPT = """You are a security compliance reviewer for Python code covering two domains:

1. HIPAA Technical Safeguards — protecting Protected Health Information (PHI) in code
2. Secrets & Credentials — detecting hardcoded API keys, tokens, passwords, and connection strings

Your job is to analyze code diffs and identify violations that static analysis may have missed. Focus on:
- PHI flowing through functions across multiple lines (data flow issues)
- Business logic that exposes PHI (e.g., unprotected API endpoints returning patient data)
- Missing access control checks before PHI is accessed or returned
- Secrets or credentials that are constructed dynamically (e.g., concatenated strings building an API key)
- Environment variable fallbacks that default to real secrets (e.g., os.getenv("KEY", "sk-real-key-here"))
- Contextual issues that require understanding the broader code intent

You will be given:
1. The PR diff (changed Python code)
2. A list of policy rules to enforce (HIPAA and Secrets)
3. Findings already caught by static analysis (do not duplicate these)

Return ONLY a JSON object with a "findings" key containing an array. Each finding must have:
- rule_id: matching one of the provided rule IDs (e.g., HIPAA-001 or SEC-008)
- file_path: path of the file with the violation
- line_number: line number in the file (use the + line numbers from the diff)
- code_snippet: the relevant code snippet (max 1 line)
- explanation: a concise explanation of why this is a violation

If you find no additional violations beyond what static analysis already caught, return {"findings": []}.
Do not invent violations. Only report what you are confident about."""


def review_with_llm(
    diff: str,
    rules: dict[str, HIPAARule],
    semgrep_findings: list[Finding],
    client: OpenAI,
    model: str = "gpt-4o",
) -> list[Finding]:
    if not diff.strip():
        return []

    rules_summary = "\n".join(
        f"- {r.rule_id} [{r.hipaa_reference}]: {r.description}"
        for r in rules.values()
    )

    already_found = "\n".join(
        f"- {f.rule_id} at {f.file_path}:{f.line_number}"
        for f in semgrep_findings
    ) or "None"

    user_message = f"""## PR Diff
```
{diff[:8000]}
```

## HIPAA Rules to Enforce
{rules_summary}

## Already Caught by Static Analysis (do not duplicate)
{already_found}

Identify any additional HIPAA violations in the diff not already listed above."""

    response = client.chat.completions.create(
        model=model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        temperature=0,
    )

    raw = response.choices[0].message.content
    try:
        parsed = json.loads(raw)
        items = parsed if isinstance(parsed, list) else parsed.get("findings", [])
    except (json.JSONDecodeError, AttributeError):
        return []

    findings: list[Finding] = []
    for item in items:
        rule_id = item.get("rule_id")
        rule = rules.get(rule_id)
        if rule is None:
            continue

        findings.append(Finding(
            rule_id=rule.rule_id,
            hipaa_reference=rule.hipaa_reference,
            category=rule.category,
            severity=rule.severity,
            file_path=item.get("file_path", "unknown"),
            line_number=int(item.get("line_number", 0)),
            code_snippet=item.get("code_snippet", ""),
            description=rule.description,
            developer_message=rule.developer_message,
            source="llm",
        ))

    return findings
