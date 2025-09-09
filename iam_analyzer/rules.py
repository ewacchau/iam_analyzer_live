"""Define risk rules as callables returning (issue, severity_score)."""
from typing import List, Tuple

Rule = Tuple[str, int]  # description, score

def _to_list(val):
    if val is None:
        return []
    return val if isinstance(val, list) else [val]

def _actions(stmt) -> List[str]:
    acts = _to_list(stmt.get("Action"))
    return [str(a).lower() for a in acts]

def _is_wildcard_resource(stmt) -> bool:
    res = stmt.get("Resource")
    return res == "*" or (isinstance(res, list) and "*" in res)

def wildcard_resource(policy: dict) -> List[Rule]:
    issues: List[Rule] = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        if _is_wildcard_resource(stmt):
            issues.append(("Allows actions on ALL resources (*)", 20))
    return issues

def wildcard_action(policy: dict) -> List[Rule]:
    issues: List[Rule] = []
    for stmt in policy.get("Statement", []):
        acts = stmt.get("Action")
        if acts == "*" or (isinstance(acts, list) and "*" in acts):
            issues.append(("Allows ALL actions (*)", 25))
    return issues

def service_wildcard_action(policy: dict) -> List[Rule]:
    """Detect service-level wildcards like iam:*, s3:* etc."""
    issues: List[Rule] = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        for a in _actions(stmt):
            if ":*" in a and not a.strip() == "*":
                sev = 20
                if _is_wildcard_resource(stmt):
                    sev = 25
                issues.append((f"Service-wide wildcard action ({a})", sev))
                break
    return issues

def notresource_allow(policy: dict) -> List[Rule]:
    issues: List[Rule] = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") == "Allow" and "NotResource" in stmt:
            issues.append(("Allow with NotResource used (broad scope)", 15))
    return issues

def passrole_wildcard(policy: dict) -> List[Rule]:
    issues: List[Rule] = []
    for stmt in policy.get("Statement", []):
        acts = _actions(stmt)
        if any(a == "iam:passrole" for a in acts):
            if _is_wildcard_resource(stmt):
                issues.append(("iam:PassRole with wildcard resource", 30))
            else:
                issues.append(("iam:PassRole present (ensure tight resource/conditions)", 10))
    return issues

def sensitive_identity_iam(policy: dict) -> List[Rule]:
    """Sensitive IAM identity operations that often allow privilege escalation."""
    sensitive = {
        "iam:createaccesskey",
        "iam:putuserpolicy",
        "iam:attachuserpolicy",
        "iam:updateaccesskey",
        "iam:updateloginprofile",
        "iam:addusertogroup",
        "iam:createuser",
        "sts:assumerole",
    }
    issues: List[Rule] = []
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        acts = set(_actions(stmt))
        hit = sorted(acts.intersection(sensitive))
        if hit:
            sev = 12
            if _is_wildcard_resource(stmt):
                sev = 22
            issues.append((f"Sensitive identity actions allowed: {', '.join(hit)}", sev))
    return issues

def s3_policy_mutation(policy: dict) -> List[Rule]:
    issues: List[Rule] = []
    risky = {"s3:putbucketpolicy", "s3:putbucketacl"}
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        acts = set(_actions(stmt))
        if acts.intersection(risky):
            sev = 10
            if _is_wildcard_resource(stmt):
                sev = 20
            issues.append(("Allows changes to S3 bucket policy/ACL", sev))
    return issues

# List of rule functions
RULE_FUNCS = [
    wildcard_resource,
    wildcard_action,
    service_wildcard_action,
    notresource_allow,
    passrole_wildcard,
    sensitive_identity_iam,
    s3_policy_mutation,
]
