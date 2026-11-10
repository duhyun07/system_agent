from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING
from security.filesystem import open_dir

if TYPE_CHECKING:
    from core.orchestrator import SystemAgent


class SourceAdapter:
    markers: tuple[str, ...] = ()

    async def inspect(self, system: "SystemAgent", source: str, task: str = "") -> dict:
        import os
        fd, _, _, _ = open_dir(system.policy, source)
        os.close(fd)
        entries = []
        for marker in self.markers:
            result = await system.skill("file_info", {"path": str(Path(source) / marker), "include_sha256": False})
            if result.ok:
                entries.append(result.output)
        if not entries:
            raise ValueError("Source directory lacks expected project markers")
        mentioned_dirs = []
        candidates = dict.fromkeys(re.findall(r"(?<![\w./-])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+", task))
        for candidate in list(candidates)[:3]:
            if any(part in (".", "..") for part in Path(candidate).parts):
                continue
            result = await system.skill("list_dir", {"path": str(Path(source) / candidate)})
            if result.ok:
                mentioned_dirs.append({"path": candidate, "entries": [item["name"] for item in result.output["entries"][:40]], "truncated": result.output["truncated"]})
        return {"source": source, "markers": entries, "mentioned_dirs": mentioned_dirs}
