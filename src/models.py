from enum import Enum
from typing import Optional
from pydantic import BaseModel


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class HIPAARule(BaseModel):
    rule_id: str
    hipaa_reference: str
    category: str
    description: str
    developer_message: str
    severity: Severity
    semgrep_rule_id: Optional[str] = None


class Finding(BaseModel):
    rule_id: str
    hipaa_reference: str
    category: str
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    developer_message: str
    source: str  # "semgrep" or "llm"


class ReviewResult(BaseModel):
    findings: list[Finding]
    passed: bool
    total_violations: int
    summary: str
