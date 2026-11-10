"""Known-issue tracking and crash-novelty judgment.

Two local stores under research/kernel/:

- known-issues.json: issues already known to be fixed or already submitted to
  kernelCTF (populated from official docs/patch info during Online setup, or
  recorded by the researcher). Each entry may carry a crash signature, a fault
  symbol, an upstream fix commit, and a CVE.
- crash-index.jsonl: an append-only index of crash signatures this platform has
  already seen (from `crash analyze` / `crash triage`), for local deduplication.

`novelty_verdict` combines three signals — the known-issue store, the local
crash index, and any upstream-fix (patch) correlation found in the kernel git
history — to decide whether a crash is already-known (duplicate or 1-day) or a
novel candidate worth a report. A crash is treated as novel only when nothing
matches; the verdict always explains its reasons.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class KnownIssuesStore:
    def __init__(self, root: Path):
        self.path = Path(root) / "research" / "kernel" / "known-issues.json"

    def list(self) -> list[dict]:
        if not self.path.is_file():
            return []
        try:
            data = json.loads(self.path.read_text())
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def add(self, entry: dict) -> dict:
        entry = {**entry, "recorded_at": datetime.now(timezone.utc).isoformat()}
        items = self.list()
        items.append(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(items, indent=2, ensure_ascii=False) + "\n")
        return entry

    def match(self, parsed: dict) -> list[dict]:
        """Return known-issue entries matching a parsed crash."""
        sig = parsed.get("signature")
        fault = (parsed.get("fault_site") or "").split("+")[0]
        hits = []
        for entry in self.list():
            if sig and entry.get("signature") == sig:
                hits.append({**entry, "match": "signature"})
            elif fault and entry.get("fault_site") and entry["fault_site"].split("+")[0] == fault:
                hits.append({**entry, "match": "fault_site"})
        return hits


class CrashIndex:
    def __init__(self, root: Path):
        self.path = Path(root) / "research" / "kernel" / "crash-index.jsonl"

    def signatures(self) -> list[dict]:
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

    def record(self, parsed: dict, sha256: str) -> bool:
        """Append a crash signature; return True if it is new to the index."""
        existing = {e.get("signature") for e in self.signatures()}
        is_new = parsed.get("signature") not in existing
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"signature": parsed.get("signature"), "bug_class": parsed.get("bug_class"), "fault_site": parsed.get("fault_site"), "sha256": sha256, "recorded_at": datetime.now(timezone.utc).isoformat()}) + "\n")
        return is_new

    def prior_matches(self, parsed: dict) -> list[dict]:
        """Entries already in the index with this crash's signature (prior occurrences)."""
        sig = parsed.get("signature")
        return [e for e in self.signatures() if e.get("signature") == sig]


def novelty_verdict(parsed: dict, *, known_hits: list[dict], prior_crashes: list[dict], patch_hits: list[dict]) -> dict:
    """Decide known vs novel from the three signals. Novel only when all are empty."""
    reasons: list[str] = []
    if known_hits:
        for h in known_hits:
            ref = h.get("fix_commit") or h.get("cve") or h.get("note") or h.get("source") or "known issue"
            reasons.append(f"Matches a known issue ({h['match']}): {ref}")
    if prior_crashes:
        reasons.append(f"Same crash signature already recorded locally ({len(prior_crashes)} prior occurrence(s))")
    if patch_hits:
        for p in patch_hits:
            reasons.append(f"An upstream commit appears to fix this area: {p['commit'][:12]} {p['subject']}")
    known = bool(reasons)
    if known:
        recommendation = (
            "Likely a duplicate or already-fixed (1-day) crash. Keep searching for a different, "
            "novel crash signature before writing a submission report."
        )
    else:
        recommendation = (
            "No known match and no upstream fix found locally. This is a NOVEL candidate crash: "
            "capture root cause from source and draft a report. It remains a hypothesis until reproduced."
        )
    return {
        "known": known,
        "novel": not known,
        "signature": parsed.get("signature"),
        "bug_class": parsed.get("bug_class"),
        "reasons": reasons,
        "known_hits": known_hits,
        "prior_crashes": prior_crashes,
        "patch_hits": patch_hits,
        "recommendation": recommendation,
    }
