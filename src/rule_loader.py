from __future__ import annotations

import json
from pathlib import Path
from src.models import HIPAARule


def load_rules(rules_dir: str | Path) -> dict[str, HIPAARule]:
    path = Path(rules_dir)
    sources = [path] if path.is_file() else sorted(path.glob("*.json"))

    rules: dict[str, HIPAARule] = {}
    for json_file in sources:
        with open(json_file) as f:
            data = json.load(f)
        for rule_data in data["rules"]:
            rule = HIPAARule(**rule_data)
            rules[rule.rule_id] = rule

    return rules


def get_rule_by_semgrep_id(rules: dict[str, HIPAARule], semgrep_rule_id: str) -> HIPAARule | None:
    for rule in rules.values():
        if rule.semgrep_rule_id == semgrep_rule_id:
            return rule
    return None
