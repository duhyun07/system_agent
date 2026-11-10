from __future__ import annotations
import os
import stat
from datetime import datetime, timezone
from typing import Any
from skills.base import BaseSkill, SkillContext
from security.filesystem import open_parent, read_bytes, sha256


class FileInfo(BaseSkill):
    name = "file_info"
    description = "Return metadata and optional SHA-256 for an authorized workspace file."
    output_properties = {"path": {"type": "string"}, "type": {"type": "string"}, "size": {"type": "integer"}, "modified_at": {"type": "string"}, "sha256": {"type": "string"}}
    output_required = ("path", "type", "size", "modified_at")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"path": {"type": "string"}, "include_sha256": {"type": "boolean", "default": False}}, "required": ["path"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        fd, _, name, relative = open_parent(context.policy, arguments["path"])
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        finally:
            os.close(fd)
        kind = "symlink" if stat.S_ISLNK(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "other"
        result = {"path": relative, "type": kind, "size": info.st_size, "modified_at": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat()}
        if arguments.get("include_sha256"):
            data, _, _ = read_bytes(context.policy, arguments["path"])
            result["sha256"] = sha256(data)
        return result
