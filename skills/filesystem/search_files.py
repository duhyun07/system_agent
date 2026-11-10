from __future__ import annotations
import asyncio
from fnmatch import fnmatch
import json
import os
from pathlib import Path
from typing import Any

from security.filesystem import open_dir
from skills.base import BaseSkill, SkillContext


class SearchFiles(BaseSkill):
    name = "search_files"
    description = "Find files by basename glob (for example *.c). This does not find directories or match paths such as mm/kasan; use list_dir with path for directories."
    output_properties = {"workspace_root": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}, "truncated": {"type": "boolean"}}
    output_required = tuple(output_properties)

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"root": {"type": "string", "default": "."}, "pattern": {"type": "string", "maxLength": 256}, "recursive": {"type": "boolean", "default": True}, "max_results": {"type": "integer", "minimum": 1, "maximum": 1000}}, "required": ["pattern"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        fd, workspace_root, _, relative = open_dir(context.policy, arguments.get("root", "."))
        paths: list[str] = []
        max_results = min(arguments.get("max_results", 100), context.policy.limits.max_entries)
        base = {"workspace_root": str(workspace_root), "paths": [], "truncated": False}
        byte_budget = max(0, context.output_limit - len(json.dumps(base, ensure_ascii=False).encode()) - 64)
        used_bytes = 0
        scanned = 0
        truncated = False

        async def walk(dirfd: int, prefix: str, depth: int) -> None:
            nonlocal used_bytes, scanned, truncated
            with os.scandir(dirfd) as listing:
                items = sorted(list(listing), key=lambda x: x.name)
            for item in items:
                if item.name in context.policy.ignored_dirs or item.name in context.policy.protected_names or item.name.startswith(".env"):
                    continue
                if scanned >= context.policy.limits.max_walk_entries:
                    truncated = True
                    return
                scanned += 1
                if scanned % 256 == 0:
                    await asyncio.sleep(0)
                if item.is_file(follow_symlinks=False) and fnmatch(item.name, arguments["pattern"]):
                    candidate = str(Path(prefix) / item.name)
                    candidate_bytes = len(json.dumps(candidate, ensure_ascii=False).encode()) + 2
                    if len(paths) >= max_results or used_bytes + candidate_bytes > byte_budget:
                        truncated = True
                        return
                    paths.append(candidate)
                    used_bytes += candidate_bytes
                if arguments.get("recursive", True) and item.is_dir(follow_symlinks=False):
                    if depth >= 20:
                        truncated = True
                        return
                    child = os.open(item.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
                    try:
                        await walk(child, str(Path(prefix) / item.name), depth + 1)
                    finally:
                        os.close(child)
                    if truncated:
                        return

        try:
            await walk(fd, relative, 0)
        finally:
            os.close(fd)
        return {"workspace_root": str(workspace_root), "paths": paths, "truncated": truncated}
