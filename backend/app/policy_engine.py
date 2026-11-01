"""Deterministic, explainable policy engine. Precedence: DENY > STEP_UP > ALLOW; default DENY."""
from dataclasses import dataclass, field

SENSITIVITY = {"low": 1, "medium": 2, "high": 3}


@dataclass
class Policy:
    id: str
    name: str
    effect: str                      # ALLOW | DENY | STEP_UP_AUTHENTICATION
    roles: list = field(default_factory=list)       # empty = any role
    resources: list = field(default_factory=list)   # empty = any resource
    mfa_verified: bool | None = None                # None = don't care
    device_compliant: bool | None = None
    min_sensitivity: int | None = None
    status: str = "active"
    version: int = 1


def _matches(p: Policy, user: dict, resource: dict, device: dict | None) -> bool:
    if p.status != "active":
        return False
    if p.roles and user["role"] not in p.roles:
        return False
    if p.resources and resource["name"] not in p.resources:
        return False
    if p.mfa_verified is not None and bool(user["mfa_verified"]) != p.mfa_verified:
        return False
    compliant = bool(device and device["compliant"])   # missing device = non-compliant
    if p.device_compliant is not None and compliant != p.device_compliant:
        return False
    if p.min_sensitivity is not None and SENSITIVITY[resource["sensitivity"]] < p.min_sensitivity:
        return False
    return True


def evaluate_access(user, resource, device, policies):
    """Returns (decision, reason, matched_policy_id, policy_version)."""
    if user is None or user["status"] != "active":
        return "DENY", "Inactive or unknown account", None, None
    if resource is None:
        return "DENY", "Unknown resource", None, None
    hits = [p for p in policies if _matches(p, user, resource, device)]
    for effect in ("DENY", "STEP_UP_AUTHENTICATION", "ALLOW"):
        for p in hits:
            if p.effect == effect:
                return effect, p.name, p.id, p.version
    return "DENY", "No applicable allow policy (default deny)", None, None
