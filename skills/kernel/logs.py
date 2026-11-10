from __future__ import annotations

from typing import Any

from skills.base import BaseSkill, SkillContext, SkillError
from adapters import kasan, kcsan


class KernelLogParse(BaseSkill):
    name = "kernel_log_parse"
    description = "Parse an UNTRUSTED kernel crash log (KASAN/KCSAN/Oops/panic/BUG) into structure: bug class, fault site, access, normalized stack frames, and a dedup signature. Does not execute anything."
    category = "kernel"
    timeout_seconds = 10
    output_properties = {"bug_class": {"type": "string"}, "fault_site": {"type": ["string", "null"]}, "access": {"type": ["object", "null"]}, "where": {"type": ["string", "null"]}, "race_kind": {"type": ["string", "null"]}, "accesses": {"type": "array"}, "frames": {"type": "array"}, "frame_count": {"type": "integer"}, "signature": {"type": "string"}, "truncated": {"type": "boolean"}}
    output_required = ("bug_class", "frames", "frame_count", "signature", "truncated")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"log": {"type": "string", "minLength": 1, "maxLength": 1000000}, "kind": {"type": "string", "enum": ["auto", "kasan", "kcsan"], "default": "auto"}}, "required": ["log"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        log = arguments["log"]
        kind = arguments.get("kind", "auto")
        if kind == "kcsan" or (kind == "auto" and "KCSAN" in log):
            return kcsan.parse_report(log)
        return kasan.parse_report(log)


class KernelCrashDeduplicate(BaseSkill):
    name = "kernel_crash_deduplicate"
    description = "Group multiple UNTRUSTED kernel crash logs by normalized signature so distinct bugs are counted once. Returns one representative per signature."
    category = "kernel"
    timeout_seconds = 15
    output_properties = {"groups": {"type": "array", "items": {"type": "object", "properties": {"signature": {"type": "string"}, "bug_class": {"type": "string"}, "count": {"type": "integer"}, "members": {"type": "array", "items": {"type": "integer"}}, "representative": {"type": "object"}}, "required": ["signature", "bug_class", "count", "members"]}}, "unique": {"type": "integer"}, "total": {"type": "integer"}}
    output_required = ("groups", "unique", "total")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"logs": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 1000000}, "minItems": 1, "maxItems": 200}}, "required": ["logs"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        logs = arguments["logs"]
        groups: dict[str, dict] = {}
        for index, log in enumerate(logs):
            parsed = kcsan.parse_report(log) if "KCSAN" in log else kasan.parse_report(log)
            sig = parsed["signature"]
            if sig not in groups:
                rep = {"bug_class": parsed["bug_class"], "fault_site": parsed.get("fault_site"), "frames": parsed["frames"][:5]}
                groups[sig] = {"signature": sig, "bug_class": parsed["bug_class"], "count": 0, "members": [], "representative": rep}
            groups[sig]["count"] += 1
            groups[sig]["members"].append(index)
        ordered = sorted(groups.values(), key=lambda g: g["count"], reverse=True)
        return {"groups": ordered, "unique": len(ordered), "total": len(logs)}
