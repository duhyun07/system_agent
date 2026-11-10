from __future__ import annotations
import difflib
from typing import Any
from skills.base import BaseSkill, SkillContext, SkillError
from security.filesystem import atomic_write, checked_path, read_bytes, sha256


class EditFile(BaseSkill):
    name = "edit_file"
    description = "Replace exact text in an existing file after hash-bound approval."
    mutating = True
    requires_approval = True
    output_properties = {"path": {"type": "string"}, "before_sha256": {"type": "string"}, "after_sha256": {"type": "string"}, "diff": {"type": "string"}}
    output_required = tuple(output_properties)

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string", "minLength": 1}, "new_text": {"type": "string"}, "expected_occurrences": {"type": "integer", "minimum": 1}, "expected_sha256": {"type": "string", "pattern": "^[a-fA-F0-9]{64}$"}}, "required": ["path", "old_text", "new_text"], "additionalProperties": False}

    def approval_payload(self, arguments: dict[str, Any], context: SkillContext) -> bytes:
        data, _, _ = read_bytes(context.policy, arguments["path"])
        return super().approval_payload({**arguments, "current_sha256": sha256(data)}, context)

    def preview(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        data, _, relative = read_bytes(context.policy, arguments["path"])
        before = data.decode("utf-8", errors="strict")
        count = before.count(arguments["old_text"])
        expected = arguments.get("expected_occurrences", 1)
        if count != expected:
            raise SkillError(f"Expected {expected} occurrences, found {count}")
        if arguments.get("expected_sha256") and sha256(data) != arguments["expected_sha256"].lower():
            raise SkillError("Stale file hash")
        after = before.replace(arguments["old_text"], arguments["new_text"])
        diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=relative, tofile=relative))
        return {"path": relative, "before_sha256": sha256(data), "after_sha256": sha256(after.encode()), "diff": diff[:8192]}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        data, _, relative = read_bytes(context.policy, arguments["path"])
        before = sha256(data)
        if arguments.get("expected_sha256") and before != arguments["expected_sha256"].lower():
            raise SkillError("Stale file hash")
        text = data.decode("utf-8", errors="strict")
        count = text.count(arguments["old_text"])
        expected = arguments.get("expected_occurrences", 1)
        if count != expected:
            raise SkillError(f"Expected {expected} occurrences, found {count}")
        changed = text.replace(arguments["old_text"], arguments["new_text"])
        preview = "".join(difflib.unified_diff(text.splitlines(True), changed.splitlines(True), fromfile=relative, tofile=relative))
        if len(preview.encode()) > context.policy.limits.max_output_bytes // 2:
            preview = preview.encode()[:context.policy.limits.max_output_bytes // 2].decode(errors="ignore")
        _, after = atomic_write(context.policy, arguments["path"], changed.encode(), overwrite=True, expected_sha256=before, preserve_mode=True)
        return {"path": relative, "before_sha256": before, "after_sha256": after, "diff": preview}
