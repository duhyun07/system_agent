from __future__ import annotations

import re
from typing import Any

from skills.base import SkillContext, SkillError
from security.filesystem import read_bytes
from skills.kernel.base import KernelSkill

_OPT = re.compile(r"^(CONFIG_[A-Z0-9_]+)$")


class KernelConfigLookup(KernelSkill):
    name = "kernel_config_lookup"
    description = "Look up a CONFIG_* option in a kernel .config file: whether it is y/m/n/unset and its value. The authoritative config is the one shipped with the official target release."
    timeout_seconds = 15
    output_properties = {"config_path": {"type": "string"}, "results": {"type": "array", "items": {"type": "object", "properties": {"option": {"type": "string"}, "state": {"type": "string"}, "value": {"type": ["string", "null"]}}, "required": ["option", "state", "value"]}}}
    output_required = ("config_path", "results")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"kernel": {"type": "string"}, "config": {"type": "string", "description": "Path to the .config file (relative to the tree or absolute in workspace)", "default": ".config"}, "options": {"type": "array", "items": {"type": "string", "pattern": "^CONFIG_[A-Z0-9_]+$"}, "minItems": 1, "maxItems": 50}}, "required": ["options"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        tree = self._tree(arguments, context)
        config_rel = arguments.get("config", ".config")
        config_path = self._subpath(tree, context, config_rel) if not config_rel.startswith("/") else None
        target = str(config_path) if config_path is not None else config_rel
        data, _, relative = read_bytes(context.policy, target)
        text = data.decode("utf-8", "replace")
        states: dict[str, tuple[str, str | None]] = {}
        for line in text.splitlines():
            line = line.strip()
            m = re.match(r"^(CONFIG_[A-Z0-9_]+)=(.*)$", line)
            if m:
                val = m.group(2)
                state = "y" if val == "y" else "m" if val == "m" else "set"
                states[m.group(1)] = (state, val)
                continue
            m = re.match(r"^# (CONFIG_[A-Z0-9_]+) is not set$", line)
            if m:
                states[m.group(1)] = ("n", None)
        results = []
        for opt in arguments["options"]:
            state, value = states.get(opt, ("unset", None))
            results.append({"option": opt, "state": state, "value": value})
        return {"config_path": relative, "results": results}
