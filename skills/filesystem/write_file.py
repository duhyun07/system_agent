from __future__ import annotations
from typing import Any
from skills.base import BaseSkill, SkillContext
from security.filesystem import atomic_write, checked_path, read_bytes, sha256


class WriteFile(BaseSkill):
    name = "write_file"
    description = "Atomically create a workspace file; overwriting requires exact approval."
    mutating = True
    output_properties = {"path": {"type": "string"}, "before_sha256": {"type": ["string", "null"]}, "after_sha256": {"type": "string"}}
    output_required = tuple(output_properties)

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}, "overwrite": {"type": "boolean", "default": False}}, "required": ["path", "content"], "additionalProperties": False}

    def destructive(self, arguments: dict[str, Any], context: SkillContext) -> bool:
        return bool(arguments.get("overwrite", False))

    def approval_payload(self, arguments: dict[str, Any], context: SkillContext) -> bytes:
        if arguments.get("overwrite", False):
            old, _, _ = read_bytes(context.policy, arguments["path"])
            return super().approval_payload({**arguments, "current_sha256": sha256(old)}, context)
        return super().approval_payload(arguments, context)

    def preview(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        import difflib
        if arguments.get("overwrite", False):
            old, _, relative = read_bytes(context.policy, arguments["path"])
            before_hash = sha256(old)
            before = old.decode("utf-8", errors="replace")
        else:
            _, _, relative = checked_path(context.policy, arguments["path"])
            before_hash, before = None, ""
        after = arguments["content"]
        diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=relative, tofile=relative))
        return {"path": relative, "before_sha256": before_hash, "after_sha256": sha256(after.encode()), "diff": diff[:8192]}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        _, _, relative = checked_path(context.policy, arguments["path"])
        expected = None
        if arguments.get("overwrite", False):
            old, _, _ = read_bytes(context.policy, arguments["path"])
            expected = sha256(old)
        before, after = atomic_write(context.policy, arguments["path"], arguments["content"].encode(), overwrite=arguments.get("overwrite", False), expected_sha256=expected)
        return {"path": relative, "before_sha256": before, "after_sha256": after}
