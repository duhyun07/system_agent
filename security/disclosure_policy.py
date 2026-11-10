from __future__ import annotations
from hashlib import sha256
from security.permissions import ApprovalStore


class DisclosurePolicy:
    """Hybrid cloud requests require one-use approval for the exact serialized payload."""
    def __init__(self, approvals: ApprovalStore):
        self.approvals = approvals

    def require(self, payload: bytes) -> str:
        self.approvals.consume("cloud_payload", payload)
        return sha256(payload).hexdigest()
