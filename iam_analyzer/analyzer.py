"""Core analysis logic."""
import json
from typing import Dict, Any, List
from .rules import RULE_FUNCS

def load_policy(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _normalize_policy_document(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Return a normalized IAM policy document.

    Accepts either a raw policy document or a wrapper with PolicyDocument.
    Ensures Statement is a list.
    """
    doc: Dict[str, Any]
    if "PolicyDocument" in policy and isinstance(policy["PolicyDocument"], dict):
        doc = policy["PolicyDocument"]
    else:
        doc = policy
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    # shallow copy to avoid mutating input
    result = dict(doc)
    result["Statement"] = stmts
    return result

def analyze_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    doc = _normalize_policy_document(policy)
    findings: List[Dict[str, Any]] = []
    total_score = 0
    for rule_fn in RULE_FUNCS:
        issues = rule_fn(doc)
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
