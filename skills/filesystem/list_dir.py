from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any
from skills.base import BaseSkill, SkillContext
from security.filesystem import open_dir


class ListDir(BaseSkill):
    name = "list_dir"
    description = "List authorized workspace entries without following directory symlinks. Large listings are truncated; use search_files for a filename."
    output_properties = {"workspace_root": {"type": "string"}, "path": {"type": "string"}, "entries": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "path": {"type": "string"}, "type": {"type": "string"}}, "required": ["name", "path", "type"]}}, "truncated": {"type": "boolean"}}
    output_required = tuple(output_properties)

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"path": {"type": "string", "default": "."}, "recursive": {"type": "boolean", "default": False}, "max_depth": {"type": "integer", "minimum": 0, "maximum": 20}, "max_entries": {"type": "integer", "minimum": 1, "maximum": 1000}}, "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        fd, workspace_root, _, relative = open_dir(context.policy, arguments.get("path", "."))
        entries: list[dict[str, str]] = []
        max_depth = min(arguments.get("max_depth", 2), 20)
        default_entries = 200 if context.origin == "llm" else context.policy.limits.max_entries
        max_entries = min(arguments.get("max_entries", default_entries), context.policy.limits.max_entries)
        base = {"workspace_root": str(workspace_root), "path": relative, "entries": [], "truncated": False}
        byte_budget = max(0, context.output_limit - len(json.dumps(base, ensure_ascii=False).encode()) - 64)
        used_bytes = 0
        truncated = False

        def walk(dirfd: int, prefix: str, depth: int) -> None:
            nonlocal used_bytes, truncated
            with os.scandir(dirfd) as listing:
                items = sorted(list(listing), key=lambda x: x.name)
            for item in items:
                if item.name in context.policy.ignored_dirs or item.name in context.policy.protected_names or item.name.startswith(".env"):
                    continue
                if len(entries) >= max_entries:
                    truncated = True
                    return
                kind = "symlink" if item.is_symlink() else "directory" if item.is_dir(follow_symlinks=False) else "file" if item.is_file(follow_symlinks=False) else "other"
                rel = str(Path(prefix) / item.name)
                entry = {"name": item.name, "path": rel, "type": kind}
                entry_bytes = len(json.dumps(entry, ensure_ascii=False).encode()) + 2
                if used_bytes + entry_bytes > byte_budget:
                    truncated = True
                    return
                used_bytes += entry_bytes
                entries.append(entry)
                if arguments.get("recursive", False) and kind == "directory":
                    if depth >= max_depth:
                        truncated = True
                        return
                    child = os.open(item.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
                    try:
                        walk(child, rel, depth + 1)
                    finally:
                        os.close(child)
                    if truncated:
                        return
        try:
            walk(fd, relative, 0)
        finally:
            os.close(fd)
        return {"workspace_root": str(workspace_root), "path": relative, "entries": entries, "truncated": truncated}
