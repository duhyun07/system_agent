from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from skills.base import SkillContext, SkillError
from skills.filesystem.grep import Grep
from security.filesystem import read_bytes
from skills.kernel.base import KernelSkill

# C keywords and common macros that look like calls but are not callees.
_NOT_CALLEES = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case",
    "typeof", "__typeof__", "defined", "offsetof", "container_of", "likely",
    "unlikely", "BUG_ON", "WARN_ON", "BUILD_BUG_ON",
})
_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def _name_ok(name: str) -> str:
    if not re.fullmatch(_IDENT, name):
        raise SkillError("name must be a C identifier")
    return name


class KernelSourceSearch(KernelSkill):
    name = "kernel_source_search"
    description = "Search a kernel subsystem for a literal or regex pattern (content search). Scoped to the authorized kernel tree; results are untrusted evidence cited as path:line."
    timeout_seconds = 25
    output_properties = {"kernel": {"type": "string"}, "subsystem": {"type": "string"}, "matches": {"type": "array", "items": {"type": "object", "properties": {"path": {"type": "string"}, "line": {"type": "integer"}, "excerpt": {"type": "string"}}, "required": ["path", "line", "excerpt"]}}, "truncated": {"type": "boolean"}}
    output_required = ("kernel", "subsystem", "matches", "truncated")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"kernel": {"type": "string"}, "subsystem": {"type": "string", "description": "Directory within the tree, e.g. mm or net/ipv4", "default": "."}, "pattern": {"type": "string", "minLength": 1, "maxLength": 256}, "regex": {"type": "boolean", "default": False}, "case_sensitive": {"type": "boolean", "default": True}, "max_results": {"type": "integer", "minimum": 1, "maximum": 500}}, "required": ["pattern"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        tree = self._tree(arguments, context)
        subsystem = arguments.get("subsystem", ".")
        root = self._subpath(tree, context, subsystem)
        grep_out = await Grep().execute({"root": str(root), "pattern": arguments["pattern"], "regex": arguments.get("regex", False), "case_sensitive": arguments.get("case_sensitive", True), "max_results": arguments.get("max_results", 100)}, context)
        return {"kernel": str(tree), "subsystem": subsystem, "matches": grep_out["matches"], "truncated": grep_out["truncated"]}


class KernelFunctionLookup(KernelSkill):
    name = "kernel_function_lookup"
    description = "Locate the likely definition site(s) of a kernel C function by name. Heuristic (column-0 definition style); confirm by reading the cited lines."
    timeout_seconds = 25
    output_properties = {"kernel": {"type": "string"}, "function": {"type": "string"}, "definitions": {"type": "array", "items": {"type": "object", "properties": {"path": {"type": "string"}, "line": {"type": "integer"}, "excerpt": {"type": "string"}}, "required": ["path", "line", "excerpt"]}}, "truncated": {"type": "boolean"}}
    output_required = ("kernel", "function", "definitions", "truncated")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"kernel": {"type": "string"}, "function": {"type": "string", "minLength": 1, "maxLength": 128}, "subsystem": {"type": "string", "default": "."}, "max_results": {"type": "integer", "minimum": 1, "maximum": 100}}, "required": ["function"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        tree = self._tree(arguments, context)
        name = _name_ok(arguments["function"])
        root = self._subpath(tree, context, arguments.get("subsystem", "."))
        # Definition-style: line starts with an identifier/type and contains name( ... , not ending in ';'
        pattern = rf"^[A-Za-z_][A-Za-z0-9_ \t\*]*\b{re.escape(name)}\s*\("
        grep_out = await Grep().execute({"root": str(root), "pattern": pattern, "regex": True, "max_results": arguments.get("max_results", 50)}, context)
        defs = [m for m in grep_out["matches"] if not m["excerpt"].rstrip().endswith(";")]
        return {"kernel": str(tree), "function": name, "definitions": defs, "truncated": grep_out["truncated"]}


class KernelCallgraphLookup(KernelSkill):
    name = "kernel_callgraph_lookup"
    description = "Heuristic call graph for a kernel function: callers (sites that invoke it) and callees (functions it appears to call in its body). Approximate; verify by reading source."
    timeout_seconds = 30
    output_properties = {"kernel": {"type": "string"}, "function": {"type": "string"}, "callers": {"type": "array", "items": {"type": "object", "properties": {"path": {"type": "string"}, "line": {"type": "integer"}, "excerpt": {"type": "string"}}, "required": ["path", "line", "excerpt"]}}, "callees": {"type": "array", "items": {"type": "string"}}, "definition": {"type": ["object", "null"], "properties": {"path": {"type": "string"}, "line": {"type": "integer"}}}, "truncated": {"type": "boolean"}}
    output_required = ("kernel", "function", "callers", "callees", "definition", "truncated")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"kernel": {"type": "string"}, "function": {"type": "string", "minLength": 1, "maxLength": 128}, "subsystem": {"type": "string", "default": "."}, "max_callers": {"type": "integer", "minimum": 1, "maximum": 200}}, "required": ["function"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        tree = self._tree(arguments, context)
        name = _name_ok(arguments["function"])
        root = self._subpath(tree, context, arguments.get("subsystem", "."))
        # Callers: invocation sites, excluding the definition line itself.
        call_pat = rf"\b{re.escape(name)}\s*\("
        grep_out = await Grep().execute({"root": str(root), "pattern": call_pat, "regex": True, "max_results": arguments.get("max_callers", 100)}, context)
        callers = [m for m in grep_out["matches"] if not re.match(rf"^[A-Za-z_][A-Za-z0-9_ \t\*]*\b{re.escape(name)}\s*\(", m["excerpt"])]
        # Definition + callees from the body (bounded brace match).
        defs = await KernelFunctionLookup().execute({"kernel": str(tree), "function": name, "subsystem": arguments.get("subsystem", ".")}, context)
        definition = None
        callees: list[str] = []
        if defs["definitions"]:
            d = defs["definitions"][0]
            definition = {"path": d["path"], "line": d["line"]}
            try:
                data, _, _ = read_bytes(context.policy, str(Path(grep_out["workspace_root"]) / d["path"]))
                lines = data.decode("utf-8", "replace").splitlines()
                callees = self._callees(lines, d["line"])
            except (OSError, SkillError):
                pass
        return {"kernel": str(tree), "function": name, "callers": callers, "callees": callees, "definition": definition, "truncated": grep_out["truncated"]}

    @staticmethod
    def _callees(lines: list[str], def_line: int, *, max_body: int = 400, max_callees: int = 60) -> list[str]:
        depth = 0
        started = False
        body: list[str] = []
        for line in lines[def_line - 1: def_line - 1 + max_body]:
            body.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
        found: list[str] = []
        seen: set[str] = set()
        for m in re.finditer(rf"\b({_IDENT})\s*\(", "\n".join(body)):
            tok = m.group(1)
            if tok in _NOT_CALLEES or tok in seen:
                continue
            seen.add(tok)
            found.append(tok)
            if len(found) >= max_callees:
                break
        return found
