from src.models import Finding, Severity
from src.findings_merger import merge_findings


def _finding(rule_id="HIPAA-001", file_path="auth.py", line_number=10, source="semgrep"):
    return Finding(
        rule_id=rule_id,
        hipaa_reference="45 CFR §164.312(b)",
        category="Audit Controls",
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=line_number,
        code_snippet="code",
        description="desc",
        developer_message="fix",
        source=source,
    )


def test_dedup_same_key_semgrep_wins():
    semgrep = _finding(source="semgrep")
    llm = _finding(source="llm")
    result = merge_findings([semgrep], [llm])
    assert len(result) == 1
    assert result[0].source == "semgrep"


def test_no_overlap_all_included():
    semgrep = _finding(file_path="a.py", line_number=1, source="semgrep")
    llm = _finding(file_path="b.py", line_number=2, source="llm")
    result = merge_findings([semgrep], [llm])
    assert len(result) == 2


def test_empty_semgrep_returns_llm_findings():
    llm = _finding(source="llm")
    result = merge_findings([], [llm])
    assert len(result) == 1
    assert result[0].source == "llm"


def test_empty_llm_returns_semgrep_findings():
    semgrep = _finding(source="semgrep")
    result = merge_findings([semgrep], [])
    assert len(result) == 1
    assert result[0].source == "semgrep"


def test_both_empty_returns_empty():
    assert merge_findings([], []) == []


def test_sorted_by_file_then_line():
    f1 = _finding(file_path="z.py", line_number=1, source="semgrep")
    f2 = _finding(file_path="a.py", line_number=5, source="llm")
    f3 = _finding(file_path="a.py", line_number=2, source="semgrep")
    result = merge_findings([f1, f3], [f2])
    assert result[0].file_path == "a.py" and result[0].line_number == 2
    assert result[1].file_path == "a.py" and result[1].line_number == 5
    assert result[2].file_path == "z.py"


def test_different_rule_same_location_both_included():
    f1 = _finding(rule_id="HIPAA-001", file_path="auth.py", line_number=10, source="semgrep")
    f2 = _finding(rule_id="HIPAA-002", file_path="auth.py", line_number=10, source="llm")
    result = merge_findings([f1], [f2])
    assert len(result) == 2
