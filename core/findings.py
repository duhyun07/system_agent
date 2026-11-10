"""Candidate-finding store with the evidence-first schema.

A finding is always a *hypothesis* until validated. The store enforces that:
`status` and `validation.status` default to unverified values, and a finding may
never be recorded as a confirmed vulnerability without a validation record whose
`reproducible` is true. Findings are appended to evidence/findings.jsonl.

Original crash evidence is immutable: `store_crash_evidence` writes the raw log
once under evidence/crashes/<sha>.log and refuses to overwrite it, so the
original artifact that a finding cites can never be silently altered.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from security.filesystem import sha256

VALID_STATUS = ("hypothesis", "under_review", "validated", "rejected")
VALID_CONFIDENCE = ("low", "medium", "high")
VALID_VALIDATION = ("not_tested", "attempted", "reproduced", "not_reproduced")

_ID_RE = re.compile(r"^KERNEL-LOCAL-\d{4,}$")


def new_finding(
    *, finding_id: str, bug_class: str, subsystem: str, source_file: str, function: str = "",
    kernel_commit: str = "", line_range: str = "", reasoning: str = "", evidence: list | None = None,
    contradictory_evidence: list | None = None, confidence: str = "low", target_config: str = "",
    fix_references: list | None = None,
) -> dict:
    if not _ID_RE.match(finding_id):
        raise ValueError("finding_id must look like KERNEL-LOCAL-0001")
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"confidence must be one of {VALID_CONFIDENCE}")
    return {
        "finding_id": finding_id,
        "status": "hypothesis",
        "bug_class": bug_class or "unknown",
        "subsystem": subsystem,
        "source_file": source_file,
        "function": function,
        "line_range": line_range,
        "kernel_commit": kernel_commit,
        "target_config": target_config,
        "reasoning": reasoning,
        "evidence": list(evidence or []),
        "contradictory_evidence": list(contradictory_evidence or []),
        "validation": {"status": "not_tested", "reproducible": None, "detail": ""},
        "confidence": confidence,
        "fix_references": list(fix_references or []),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }


class FindingsStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / "evidence" / "findings.jsonl"
        self.crashes_dir = self.root / "evidence" / "crashes"

    def add(self, finding: dict) -> dict:
        self._validate(finding)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(finding, ensure_ascii=False) + "\n")
        return finding

    def list(self) -> list[dict]:
        if not self.path.is_file():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    def get(self, finding_id: str) -> dict | None:
        # Last record wins (findings may be re-appended as they are updated).
        found = None
        for item in self.list():
            if item.get("finding_id") == finding_id:
                found = item
        return found

    @staticmethod
    def _validate(finding: dict) -> None:
        if finding.get("status") not in VALID_STATUS:
            raise ValueError(f"status must be one of {VALID_STATUS}")
        val = finding.get("validation") or {}
        if val.get("status") not in VALID_VALIDATION:
            raise ValueError(f"validation.status must be one of {VALID_VALIDATION}")
        # Evidence-first invariant: cannot be 'validated' without a reproduced result.
        if finding.get("status") == "validated" and not (val.get("status") == "reproduced" and val.get("reproducible") is True):
            raise ValueError("A finding may be 'validated' only with validation.status='reproduced' and reproducible=true")

    def store_crash_evidence(self, raw: str) -> dict:
        """Write an original crash log immutably and return its reference."""
        self.crashes_dir.mkdir(parents=True, exist_ok=True)
        data = raw.encode("utf-8", "replace")
        digest = sha256(data)
        dest = self.crashes_dir / f"{digest}.log"
        if dest.exists():
            return {"sha256": digest, "path": str(dest), "stored": False, "note": "identical evidence already stored (immutable)"}
        # O_EXCL: never overwrite existing evidence.
        import os
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        return {"sha256": digest, "path": str(dest), "stored": True}
