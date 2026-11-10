from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode()
    return hashlib.sha256(data).hexdigest()


class SkillAuditLogger:
    def __init__(self, path: Path):
        self.path = path
        self._lock = asyncio.Lock()

    async def record(self, event: dict[str, Any]) -> None:
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Arguments and returned content are never placed in the log.
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
