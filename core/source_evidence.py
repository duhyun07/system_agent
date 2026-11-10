from __future__ import annotations

import re
from pathlib import Path

from core.policy import Policy
from security.filesystem import checked_path
from skills.base import SkillResult


_CITATION = re.compile(r"(?<![\w./-])(?P<path>/?[A-Za-z0-9_.+/-]+):(?P<line>[1-9][0-9]*)")


class SourceEvidence:
    """Track source lines actually returned by read_file or grep in a task."""

    def __init__(self, policy: Policy, source_root: str):
        self.policy = policy
        self.source_root = Path(source_root).resolve()
        self.lines: dict[str, list[tuple[int, int]]] = {}

    def _record(self, absolute: Path, start: int, end: int) -> None:
        try:
            source_relative = absolute.relative_to(self.source_root)
        except ValueError:
            return
        if end < start:
            return
        for alias in (str(source_relative), str(absolute)):
            self.lines.setdefault(alias, []).append((start, end))

    def observe(self, name: str, arguments: dict, result: SkillResult) -> None:
        if not result.ok:
            return
        if name == "read_file":
            path = Path(arguments["path"])
            root, _, relative = checked_path(self.policy, str(path if path.is_absolute() else self.source_root / path))
            content = result.output["content"]
            count = len(content.splitlines())
            if result.output["truncated"] and not content.endswith("\n"):
                count -= 1
            start = result.output["start_line"]
            self._record(root / relative, start, start + count - 1)
        elif name == "grep":
            root = Path(result.output["workspace_root"])
            for match in result.output["matches"]:
                self._record(root / match["path"], match["line"], match["line"])

    def check(self, answer: str) -> str | None:
        if not self.lines:
            return "No source lines were read through read_file or grep"
        citations = list(_CITATION.finditer(answer))
        if not citations:
            return "No path:line citations were provided"
        for citation in citations:
            path, line = citation.group("path"), int(citation.group("line"))
            if not any(start <= line <= end for start, end in self.lines.get(path, [])):
                return f"Unverified citation: {path}:{line}"
        return None
