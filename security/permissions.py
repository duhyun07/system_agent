from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Callable
from core.policy import Policy


class PermissionDenied(Exception):
    pass


class ApprovalRequired(PermissionDenied):
    def __init__(self, operation: str, payload_hash: str):
        self.operation, self.payload_hash = operation, payload_hash
        super().__init__(f"Approval required for {operation}; SHA-256 {payload_hash}")


@dataclass
class ApprovalStore:
    """One-use approvals bound to operation and exact bytes."""
    approved: set[tuple[str, str]] = field(default_factory=set)

    def grant(self, operation: str, payload: bytes) -> str:
        fingerprint = sha256(payload).hexdigest()
        self.approved.add((operation, fingerprint))
        return fingerprint

    def consume(self, operation: str, payload: bytes) -> None:
        fingerprint = sha256(payload).hexdigest()
        key = (operation, fingerprint)
        if key not in self.approved:
            raise ApprovalRequired(operation, fingerprint)
        self.approved.remove(key)


class SkillPermissionManager:
    def __init__(self, policy: Policy, approvals: ApprovalStore | None = None):
        self.policy = policy
        self.approvals = approvals or ApprovalStore()

    def available(self, skill: object) -> bool:
        category = getattr(skill, "category", "filesystem")
        name = getattr(skill, "name")
        rule = self.policy.skill_rules.get(category, {}).get(name)
        if self.policy.skill_rules and rule is None:
            return False
        if isinstance(rule, dict):
            rule = rule.get(self.policy.mode, "deny")
        if rule not in (None, "allow", "workspace_only", "approval_required", "allowlisted", "allowlisted_and_payload_approval"):
            return False
        if category == "network":
            # Network skills are gated by the domain allowlist (and per-mode skill_rules
            # above), not by the mode itself; an empty allowlist denies all network.
            return bool(self.policy.allowed_domains)
        return True

    def authorize(self, skill: object, payload: bytes, *, destructive: bool = False) -> None:
        name = getattr(skill, "name")
        if not self.available(skill):
            raise PermissionDenied(f"{name} is unavailable in {self.policy.mode} mode or network policy denies it")
        rule = self.policy.skill_rules.get(getattr(skill, "category", "filesystem"), {}).get(name)
        if getattr(skill, "requires_approval", False) or destructive or rule == "approval_required" or (getattr(skill, "category", "") == "network" and self.policy.mode == "hybrid"):
            self.approvals.consume(name, payload)
