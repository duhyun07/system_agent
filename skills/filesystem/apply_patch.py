from __future__ import annotations
import difflib
from typing import Any
from skills.base import BaseSkill, SkillContext, SkillError
from security.filesystem import atomic_write, read_bytes, sha256


class ApplyPatch(BaseSkill):
    name = "apply_patch"
    description = "Apply exact text patches to existing files after preview and approval."
    mutating = True
    requires_approval = True
    output_properties = {"changes": {"type": "array", "items": {"type": "object", "properties": {"path": {"type": "string"}, "diff": {"type": "string"}, "before_sha256": {"type": "string"}, "after_sha256": {"type": "string"}}, "required": ["path", "diff", "before_sha256", "after_sha256"]}}}
    output_required = ("changes",)

    def schema(self) -> dict[str, Any]:
        item = {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string", "minLength": 1}, "new_text": {"type": "string"}, "expected_sha256": {"type": "string", "pattern": "^[a-fA-F0-9]{64}$"}}, "required": ["path", "old_text", "new_text", "expected_sha256"], "additionalProperties": False}
        return {"type": "object", "properties": {"changes": {"type": "array", "items": item, "minItems": 1, "maxItems": 20}}, "required": ["changes"], "additionalProperties": False}

    def _prepare(self, arguments: dict[str, Any], context: SkillContext) -> list[tuple[str, bytes, bytes, str]]:
        prepared = []
        seen = set()
        for change in arguments["changes"]:
            path = change["path"]
            if path in seen:
                raise SkillError("Duplicate patch path")
            seen.add(path)
            old, _, relative = read_bytes(context.policy, path)
            before = sha256(old)
            if before != change["expected_sha256"].lower():
                raise SkillError(f"Stale file hash: {relative}")
            text = old.decode("utf-8", errors="strict")
            if text.count(change["old_text"]) != 1:
                raise SkillError(f"Patch text must occur exactly once: {relative}")
            new = text.replace(change["old_text"], change["new_text"], 1).encode()
            prepared.append((path, old, new, relative))
        return prepared

    def approval_payload(self, arguments: dict[str, Any], context: SkillContext) -> bytes:
        prepared = self._prepare(arguments, context)
        return super().approval_payload({"changes": arguments["changes"], "current_hashes": {r: sha256(old) for _, old, _, r in prepared}}, context)

    def preview(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        prepared = self._prepare(arguments, context)
        previews = []
        for _, old, new, relative in prepared:
            diff = "".join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True), fromfile=relative, tofile=relative))
            previews.append({"path": relative, "diff": diff[:8192], "before_sha256": sha256(old), "after_sha256": sha256(new)})
        return {"changes": previews}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        prepared = self._prepare(arguments, context)
        previews = []
        for _, old, new, relative in prepared:
            diff = "".join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True), fromfile=relative, tofile=relative))
            previews.append({"path": relative, "diff": diff[:4096], "before_sha256": sha256(old), "after_sha256": sha256(new)})
        if sum(len(p["diff"].encode()) for p in previews) > context.policy.limits.max_output_bytes // 2:
            raise SkillError("Patch preview exceeds output limit")
        for path, old, new, _ in prepared:
            atomic_write(context.policy, path, new, overwrite=True, expected_sha256=sha256(old), preserve_mode=True)
        return {"changes": previews}
