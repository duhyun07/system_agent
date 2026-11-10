from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable
from pathlib import Path
from core.policy import Policy
from security.audit import SkillAuditLogger
from security.permissions import SkillPermissionManager


class SkillError(Exception):
    pass


@dataclass
class SkillContext:
    policy: Policy
    permissions: SkillPermissionManager
    audit: SkillAuditLogger
    origin: str = "cli"
    task_id: str = "direct"
    cancellation: Any = None
    progress: Callable[[str], None] | None = None
    source_root: Path | None = None

    @property
    def output_limit(self) -> int:
        if self.origin == "llm":
            return min(self.policy.limits.max_output_bytes, self.policy.limits.max_model_tool_output_bytes)
        return self.policy.limits.max_output_bytes


@dataclass
class SkillResult:
    name: str
    ok: bool
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "output": self.output, "error": self.error}


class BaseSkill(ABC):
    name: str
    description: str
    category: str = "filesystem"
    mutating: bool = False
    requires_approval: bool = False
    cli_only: bool = False  # never offered to or callable by the LLM (origin="llm")
    timeout_seconds: float = 30
    output_properties: dict[str, Any] = {}
    output_required: tuple[str, ...] = ()

    @abstractmethod
    def schema(self) -> dict[str, Any]: ...

    def output_schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": self.output_properties, "required": list(self.output_required), "additionalProperties": not bool(self.output_properties)}

    @abstractmethod
    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]: ...

    def approval_payload(self, arguments: dict[str, Any], context: SkillContext) -> bytes:
        import json
        return json.dumps(arguments, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()

    def destructive(self, arguments: dict[str, Any], context: SkillContext) -> bool:
        return False

    def preview(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        return {"arguments": arguments}
