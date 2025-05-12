"""Core analysis logic."""
import json
from typing import Dict, Any, List
from .rules import RULE_FUNCS

def load_policy(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def analyze_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    total_score = 0
    for rule_fn in RULE_FUNCS:
        issues = rule_fn(policy)
        for desc, score in issues:
            findings.append({"issue": desc, "score": score})
            total_score += score
    risk_level = (
        "Low" if total_score < 20 else
        "Medium" if total_score < 50 else
        "High"
    )
    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "findings": findings
    }
