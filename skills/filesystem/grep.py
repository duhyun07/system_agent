from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Any
import regex
from skills.base import BaseSkill, SkillContext, SkillError
from skills.filesystem.list_dir import ListDir
from security.filesystem import read_bytes


class Grep(BaseSkill):
    name = "grep"
    description = "Search bounded workspace text with literal or time-limited regex matching."
    output_properties = {"workspace_root": {"type": "string"}, "matches": {"type": "array", "items": {"type": "object", "properties": {"path": {"type": "string"}, "line": {"type": "integer"}, "excerpt": {"type": "string"}}, "required": ["path", "line", "excerpt"]}}, "truncated": {"type": "boolean"}, "scanned_bytes": {"type": "integer"}}
    output_required = tuple(output_properties)

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"root": {"type": "string", "default": "."}, "pattern": {"type": "string", "minLength": 1, "maxLength": 256}, "regex": {"type": "boolean", "default": False}, "case_sensitive": {"type": "boolean", "default": True}, "max_results": {"type": "integer", "minimum": 1, "maximum": 1000}}, "required": ["pattern"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        listed = await ListDir().execute({"path": arguments.get("root", "."), "recursive": True, "max_depth": 20}, context)
        flags = 0 if arguments.get("case_sensitive", True) else regex.IGNORECASE
        pattern = arguments["pattern"] if arguments.get("regex", False) else regex.escape(arguments["pattern"])
        try:
            compiled = regex.compile(pattern, flags)
        except regex.error as exc:
            raise SkillError(str(exc)) from exc
        max_results = min(arguments.get("max_results", 100), context.policy.limits.max_entries)
        matches = []
        scanned = 0
        truncated = listed["truncated"]
        base = {"workspace_root": listed["workspace_root"], "matches": [], "truncated": False, "scanned_bytes": 0}
        byte_budget = max(0, context.output_limit - len(json.dumps(base, ensure_ascii=False).encode()) - 64)
        used_bytes = 0
        output_full = False
        for item in listed["entries"]:
            if item["type"] != "file":
                continue
            try:
                data, _, _ = read_bytes(context.policy, str(Path(listed["workspace_root"]) / item["path"]))
            except (OSError, SkillError):
                continue
            if b"\x00" in data:
                continue
            scanned += len(data)
            if scanned > context.policy.limits.max_scan_bytes:
                truncated = True
                break
            for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if number % 50 == 0:
                    await asyncio.sleep(0)
                try:
                    found = compiled.search(line[:8192], timeout=0.02)
                except TimeoutError:
                    raise SkillError("Regex evaluation timed out")
                if found:
                    match = {"path": item["path"], "line": number, "excerpt": line[:300]}
                    match_bytes = len(json.dumps(match, ensure_ascii=False).encode()) + 2
                    if used_bytes + match_bytes > byte_budget:
                        truncated = True
                        output_full = True
                        break
                    matches.append(match)
                    used_bytes += match_bytes
                    if len(matches) >= max_results:
                        truncated = True
                        output_full = True
                        break
            if output_full:
                break
        return {"workspace_root": listed["workspace_root"], "matches": matches, "truncated": truncated, "scanned_bytes": scanned}
