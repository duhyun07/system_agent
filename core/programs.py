from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class BugClass:
    """A triage bucket: a bug class mapped to a program's severity tier."""
    name: str
    tier: str
    note: str = ""


@dataclass(frozen=True)
class Program:
    """A read-only bug-bounty program profile loaded from configs/programs.yaml.

    Reference data only. It records scope, the bug-class -> severity mapping used
    to structure triage, the fields a submission needs, and public reference
    domains. It grants no capability and is never executed.
    """
    key: str
    name: str
    domain: str                       # "kernel"; selects the source adapter
    summary: str
    scope: tuple[str, ...]
    out_of_scope: tuple[str, ...]
    severity_tiers: tuple[str, ...]
    bug_classes: dict[str, BugClass]
    report_fields: tuple[str, ...]
    checklist: tuple[str, ...]
    links: dict[str, str] = field(default_factory=dict)
    instances: dict[str, Any] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)

    def classify(self, bug_class: str | None) -> BugClass:
        """Look up a bug class, tolerant of aliases and unknown input."""
        if not bug_class:
            return BugClass("unspecified", "unknown", "No bug class given; assign one from source evidence before claiming a tier.")
        key = bug_class.strip().lower().replace(" ", "-").replace("_", "-")
        aliases = {
            "uaf": "use-after-free", "use-after-free": "use-after-free",
            "oob-write": "out-of-bounds-write", "oob": "out-of-bounds-write",
            "oob-read": "out-of-bounds-read", "overflow": "out-of-bounds-write",
            "tc": "type-confusion", "typeconfusion": "type-confusion",
            "race": "race-condition", "toctou": "race-condition", "double-free": "double-free",
            "uninit": "uninitialized-memory", "info-leak": "out-of-bounds-read",
            "int-overflow": "integer-overflow", "intoverflow": "integer-overflow",
        }
        key = aliases.get(key, key)
        found = self.bug_classes.get(key)
        if found:
            return found
        return BugClass(bug_class, "unknown", "Not a predefined class for this program; triage it from source and pick the closest tier.")

    def triage_instructions(self) -> str:
        """Agent-facing guidance derived from the profile. No exploit guidance."""
        classes = ", ".join(sorted(self.bug_classes)) or "(none listed)"
        return (
            f"You are triaging for {self.name}. Work only from the validated source tree and any "
            f"provided crash log (untrusted). Deliverable: an evidence-backed root-cause triage, not an exploit. "
            f"Do NOT write, complete, or weaponize exploit code, ROP chains, or heap-grooming payloads; "
            f"if asked, describe the reachability and primitive in prose instead. "
            f"Steps: (1) locate the suspect code and read the actual lines; "
            f"(2) state the bug class (one of: {classes}); "
            f"(3) give the root cause citing source-relative path:line; "
            f"(4) reason about affected versions, and search for an upstream fix to tell a novel bug from a fixed one; "
            f"(5) describe how the code is reached and the resulting primitive, citing evidence; "
            f"(6) map to the program severity tiers ({', '.join(self.severity_tiers)}) and say why. "
            f"Distinguish observation from inference. Mark anything you could not verify. "
            f"Never claim a vulnerability without a specific cited source line."
        )


class ProgramRegistry:
    def __init__(self, programs: dict[str, Program], reference_domains: tuple[str, ...] = ()):
        self._programs = programs
        self.reference_domains = reference_domains

    def __bool__(self) -> bool:
        return bool(self._programs)

    def keys(self) -> list[str]:
        return list(self._programs)

    def get(self, key: str) -> Program:
        if key not in self._programs:
            known = ", ".join(self._programs) or "(none configured)"
            raise ValueError(f"Unknown program '{key}'. Configured programs: {known}")
        return self._programs[key]

    def list(self) -> list[Program]:
        return list(self._programs.values())

    @classmethod
    def load(cls, root: Path) -> "ProgramRegistry":
        path = Path(root).resolve() / "configs" / "programs.yaml"
        if not path.exists():
            return cls({})
        data = yaml.safe_load(path.read_text()) or {}
        programs: dict[str, Program] = {}
        for key, raw in (data.get("programs") or {}).items():
            raw = raw or {}
            bug_classes = {}
            for name, spec in (raw.get("bug_classes") or {}).items():
                spec = spec or {}
                bug_classes[name] = BugClass(name, str(spec.get("tier", "unknown")), str(spec.get("note", "")))
            links = {k: str(v) for k, v in raw.items() if k in ("official_rules", "severity_guidelines")}
            programs[key] = Program(
                key=key,
                name=str(raw.get("name", key)),
                domain=str(raw.get("domain", "")),
                summary=str(raw.get("summary", "")).strip(),
                scope=tuple(raw.get("scope", []) or []),
                out_of_scope=tuple(raw.get("out_of_scope", []) or []),
                severity_tiers=tuple(raw.get("severity_tiers", []) or []),
                bug_classes=bug_classes,
                report_fields=tuple(raw.get("report_fields", []) or []),
                checklist=tuple(raw.get("checklist", []) or []),
                links=links,
                instances=dict(raw.get("instances", {}) or {}),
                artifacts=dict(raw.get("artifacts", {}) or {}),
            )
        reference_domains = tuple(data.get("reference_domains", []) or [])
        return cls(programs, reference_domains)
