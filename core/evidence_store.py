from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class EvidenceStore:
    def __init__(self, root: Path):
        self.path = root / "evidence" / "index.jsonl"

    def add(self, source: str, sha256: str, note: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"source": source, "sha256": sha256, "note": note, "recorded_at": datetime.now(timezone.utc).isoformat()}) + "\n")
