from __future__ import annotations

from typing import Any

from skills.base import SkillContext, SkillError
from skills.kernel.base import KernelSkill
from adapters import git


class KernelCommitDiff(KernelSkill):
    name = "kernel_commit_diff"
    description = "Read-only git diff/show/log over a local authorized kernel checkout, to compare commits and judge whether a fix is complete. Never fetches, never writes."
    timeout_seconds = 30
    output_properties = {"tree": {"type": "string"}, "operation": {"type": "string"}, "output": {"type": "string"}, "commits": {"type": "array"}}
    output_required = ("tree", "operation")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"kernel": {"type": "string"}, "operation": {"type": "string", "enum": ["show", "diff", "log", "head"]}, "rev": {"type": "string", "maxLength": 200}, "base": {"type": "string", "maxLength": 200}, "target": {"type": "string", "maxLength": 200}, "path": {"type": "string", "maxLength": 300}, "count": {"type": "integer", "minimum": 1, "maximum": 200}, "stat_only": {"type": "boolean", "default": False}}, "required": ["operation"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        tree = str(self._tree(arguments, context))
        op = arguments["operation"]
        try:
            if op == "head":
                info = await git.head(context.policy, tree)
                return {"tree": info["tree"], "operation": op, "output": f"HEAD {info['head']} ({info['describe']})"}
            if op == "show":
                if "rev" not in arguments:
                    raise SkillError("'show' requires 'rev'")
                out = await git.show(context.policy, tree, arguments["rev"], stat_only=arguments.get("stat_only", False), max_bytes=context.output_limit)
                return {"tree": tree, "operation": op, "output": out}
            if op == "diff":
                if "base" not in arguments or "target" not in arguments:
                    raise SkillError("'diff' requires 'base' and 'target'")
                out = await git.diff(context.policy, tree, arguments["base"], arguments["target"], path=arguments.get("path"), stat_only=arguments.get("stat_only", False), max_bytes=context.output_limit)
                return {"tree": tree, "operation": op, "output": out}
            commits = await git.log(context.policy, tree, arguments.get("rev", "HEAD"), count=arguments.get("count", 20), path=arguments.get("path"))
            return {"tree": tree, "operation": op, "commits": commits}
        except git.GitError as exc:
            raise SkillError(str(exc)) from exc
