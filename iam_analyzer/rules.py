"""Define risk rules as callables returning (issue, severity_score)."""
from typing import List, Dict, Tuple

Rule = Tuple[str, int]  # description, score

def wildcard_resource(policy: dict) -> List[Rule]:
    issues = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        res = stmt.get("Resource")
        if res == "*" or (isinstance(res, list) and "*" in res):
            issues.append(("Allows actions on ALL resources (*)", 20))
    return issues

def wildcard_action(policy: dict) -> List[Rule]:
    issues = []
    for stmt in policy.get("Statement", []):
        acts = stmt.get("Action")
        if acts == "*" or (isinstance(acts, list) and "*" in acts):
            issues.append(("Allows ALL actions (*)", 25))
    return issues

def passrole_wildcard(policy: dict) -> List[Rule]:
    issues = []
    for stmt in policy.get("Statement", []):
        acts = stmt.get("Action", [])
        acts = acts if isinstance(acts, list) else [acts]
        if any(a.lower() == "iam:passrole" for a in acts):
            res = stmt.get("Resource")
            if res == "*" or (isinstance(res, list) and "*" in res):
                issues.append(("iam:PassRole with wildcard resource", 30))
    return issues

# List of rule functions
RULE_FUNCS = [wildcard_resource, wildcard_action, passrole_wildcard]
