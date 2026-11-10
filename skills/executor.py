from __future__ import annotations

import asyncio
import json
from pathlib import Path
from jsonschema import Draft202012Validator
from skills.base import SkillContext, SkillError, SkillResult
from skills.registry import SkillRegistry
from security.audit import digest


class SkillExecutor:
    def __init__(self, registry: SkillRegistry, context: SkillContext):
        self.registry, self.context = registry, context

    def definitions(self, *, mutating: bool | None = None) -> list[dict]:
        return [
            {"type": "function", "name": skill.name, "description": skill.description, "parameters": skill.schema(), "strict": False}
            for skill in self.registry.list()
            if self.context.permissions.available(skill) and (mutating is None or skill.mutating == mutating)
            and not (skill.cli_only and self.context.origin == "llm")
        ]

    def _source_arguments(self, name: str, arguments: dict, category: str, mutating: bool) -> dict:
        source = self.context.source_root
        if source is None or self.context.origin != "llm" or category != "filesystem" or mutating:
            return arguments
        field = "path" if name in ("read_file", "list_dir", "file_info") else "root" if name in ("search_files", "grep") else None
        if field is None:
            return arguments
        value = arguments.get(field, ".")
        if not isinstance(value, str):
            return arguments  # JSON Schema reports the invalid argument.
        raw = Path(value)
        if ".." in raw.parts:
            raise SkillError("Path traversal rejected")
        absolute = raw if raw.is_absolute() else source / raw
        if absolute != source and source not in absolute.parents:
            raise SkillError("Path outside task source root")
        return {**arguments, field: str(absolute)}

    @staticmethod
    def _clip(value: object, limit: int = 120) -> str:
        text = " ".join(str(value).split())  # collapse newlines/whitespace for tidy one-line logs
        return text if len(text) <= limit else text[: limit - 1] + "…"

    def _result_preview(self, name: str, output: dict) -> list[str]:
        # Short, truncated preview of fetched/searched content for the progress log.
        # Content is untrusted; it is only displayed, never interpreted.
        lines: list[str] = []
        if name == "web_search" and isinstance(output.get("results"), list):
            for i, item in enumerate(output["results"][:3], 1):
                if isinstance(item, dict):
                    lines.append(f"[{i}] {self._clip(item.get('title', ''), 80)} — {self._clip(item.get('url', ''), 100)}")
        elif name == "fetch":
            status = output.get("status_code", "?")
            flag = "" if output.get("ok", True) else " (HTTP 오류)"
            lines.append(f"{status}{flag} {self._clip(output.get('final_url', ''), 100)}")
            content = output.get("content")
            if content not in (None, ""):
                lines.append(f"content: {self._clip(content, 160)}")
        return lines

    async def execute(self, name: str, arguments: dict, *, allowed_names: set[str] | None = None) -> SkillResult:
        started = asyncio.get_running_loop().time()
        progress = self.context.progress
        if progress:
            safe_fields = []
            if isinstance(arguments, dict):
                for key in ("url", "query", "path", "root", "pattern", "start_line", "end_line", "recursive"):
                    if key in arguments:
                        value = repr(arguments[key])
                        safe_fields.append(f"{key}={value[:100]}")
            progress(f"skill {name} 시작" + (f" ({', '.join(safe_fields)})" if safe_fields else ""))
        try:
            if allowed_names is not None and name not in allowed_names:
                raise SkillError("Skill was not offered for this task")
            skill = self.registry.get(name)
            if skill.cli_only and self.context.origin == "llm":
                raise SkillError("Skill is not available to the model; it is CLI-only and requires explicit human action")
            if not self.context.permissions.available(skill):
                raise SkillError("Skill is unavailable under current policy")
            if not isinstance(arguments, dict):
                raise SkillError("Arguments must be an object")
            Draft202012Validator(skill.schema()).validate(arguments)
            effective = self._source_arguments(name, arguments, skill.category, skill.mutating)
            payload = skill.approval_payload(effective, self.context)
            self.context.permissions.authorize(skill, payload, destructive=skill.destructive(effective, self.context))
            if self.context.cancellation is not None and self.context.cancellation.is_set():
                raise asyncio.CancelledError()
            timeout = min(skill.timeout_seconds, self.context.policy.limits.max_tool_seconds)
            output = await asyncio.wait_for(skill.execute(effective, self.context), timeout=timeout)
            if not isinstance(output, dict):
                raise SkillError("Skill returned a non-object result")
            Draft202012Validator(skill.output_schema()).validate(output)
            encoded = json.dumps(output, ensure_ascii=False, default=str).encode()
            if len(encoded) > self.context.output_limit:
                raise SkillError("Skill output exceeds configured limit")
            result = SkillResult(name, True, output)
        except asyncio.CancelledError:
            raise
        except FileNotFoundError as exc:
            hint = f" Relative paths are under {self.context.source_root}; use '.' for the source root and search_files before guessing filenames." if self.context.source_root else ""
            result = SkillResult(name, False, error=f"FileNotFoundError: {exc}.{hint}")
        except Exception as exc:
            result = SkillResult(name, False, error=f"{type(exc).__name__}: {exc}")
        await self.context.audit.record({
            "task_id": self.context.task_id, "origin": self.context.origin, "skill": name,
            "arguments_sha256": digest(arguments), "ok": result.ok,
            "result_sha256": digest(result.output if result.ok else result.error),
            "elapsed_ms": round((asyncio.get_running_loop().time() - started) * 1000),
        })
        if progress:
            elapsed = round((asyncio.get_running_loop().time() - started) * 1000)
            if result.ok:
                counts = [f"{key}={len(result.output[key])}" for key in ("entries", "paths", "matches", "results") if isinstance(result.output.get(key), list)]
                if result.output.get("truncated"):
                    counts.append("truncated=true")
                progress(f"skill {name} 완료 ({elapsed}ms" + (f", {', '.join(counts)}" if counts else "") + ")")
                for line in self._result_preview(name, result.output):
                    progress("    " + line)
            else:
                progress(f"skill {name} 실패 ({elapsed}ms): {result.error}")
        return result
