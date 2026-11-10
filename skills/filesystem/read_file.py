from __future__ import annotations
from typing import Any
from skills.base import BaseSkill, SkillContext, SkillError
from security.filesystem import read_bytes


class ReadFile(BaseSkill):
    name = "read_file"
    description = "Read bounded UTF-8 text from an authorized workspace file. Invalid UTF-8 is replaced."
    output_properties = {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}, "total_lines": {"type": "integer"}, "content": {"type": "string"}, "truncated": {"type": "boolean"}, "decoding_errors": {"type": "string"}}
    output_required = tuple(output_properties)

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1}, "end_line": {"type": "integer", "minimum": 1}}, "required": ["path"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        data, _, relative = read_bytes(context.policy, arguments["path"])
        lines = data.decode("utf-8", errors="replace").splitlines(keepends=True)
        start, end = arguments.get("start_line", 1), arguments.get("end_line", len(lines))
        if end < start:
            raise SkillError("end_line must be >= start_line")
        text = "".join(lines[start - 1:end])
        cap = max(0, context.output_limit - 1024)
        encoded = text.encode("utf-8")
        truncated = len(encoded) > cap
        if truncated:
            text = encoded[:cap].decode("utf-8", errors="ignore")
        returned_lines = len(text.splitlines())
        actual_end = start + returned_lines - 1 if truncated else min(end, len(lines))
        return {"path": relative, "start_line": start, "end_line": actual_end, "total_lines": len(lines), "content": text, "truncated": truncated, "decoding_errors": "replace"}
