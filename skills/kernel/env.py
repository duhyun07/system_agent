from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from skills.base import BaseSkill, SkillContext, SkillError
from security.filesystem import read_bytes, sha256
from skills.kernel.base import KernelSkill
from adapters import qemu, kcov

_MK = re.compile(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION|NAME)\s*=\s*(.*)$")


class KernelBuildInfo(KernelSkill):
    name = "kernel_build_info"
    description = "Read build provenance from an authorized kernel tree: Makefile version, kernel.release if built, .config checksum, and kernelCTF metadata.json if present. Records exact identity for findings."
    timeout_seconds = 15
    output_properties = {"kernel": {"type": "string"}, "version": {"type": ["string", "null"]}, "makefile_version": {"type": "object"}, "kernel_release": {"type": ["string", "null"]}, "config_sha256": {"type": ["string", "null"]}, "metadata": {"type": ["object", "null"]}}
    output_required = ("kernel", "makefile_version")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"kernel": {"type": "string"}}, "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        tree = self._tree(arguments, context)
        mk: dict[str, str] = {}
        try:
            data, _, _ = read_bytes(context.policy, str(tree / "Makefile"))
            for line in data.decode("utf-8", "replace").splitlines()[:20]:
                m = _MK.match(line.strip())
                if m:
                    mk[m.group(1).lower()] = m.group(2).strip()
        except (OSError, SkillError):
            pass
        version = None
        if mk.get("version") and mk.get("patchlevel"):
            version = f"{mk['version']}.{mk['patchlevel']}"
            if mk.get("sublevel"):
                version += f".{mk['sublevel']}"
            version += mk.get("extraversion", "")
        release = None
        for rel in ("include/config/kernel.release",):
            try:
                data, _, _ = read_bytes(context.policy, str(tree / rel))
                release = data.decode("utf-8", "replace").strip()
                break
            except (OSError, SkillError):
                continue
        config_sha = None
        try:
            data, _, _ = read_bytes(context.policy, str(tree / ".config"))
            config_sha = sha256(data)
        except (OSError, SkillError):
            pass
        metadata = None
        for name in ("metadata.json",):
            try:
                data, _, _ = read_bytes(context.policy, str(tree / name))
                metadata = json.loads(data.decode("utf-8", "replace"))
                break
            except (OSError, SkillError, ValueError):
                continue
        return {"kernel": str(tree), "version": version, "makefile_version": mk, "kernel_release": release, "config_sha256": config_sha, "metadata": metadata}


class KernelCoverageRead(KernelSkill):
    name = "kernel_coverage_read"
    description = "Read a KCOV/fuzzing coverage summary file already produced by an authorized run (text or JSON). Does not instrument, build, or run anything."
    timeout_seconds = 10
    output_properties = {"path": {"type": "string"}, "format": {"type": "string"}, "metrics": {"type": "object"}, "raw_keys": {"type": "array"}}
    output_required = ("path", "format", "metrics")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"kernel": {"type": "string"}, "path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        rel = arguments["path"]
        if rel.startswith("/"):
            target = rel
        else:
            tree = self._tree(arguments, context)
            target = str(self._subpath(tree, context, rel))
        data, _, relative = read_bytes(context.policy, target)
        summary = kcov.parse_summary(data.decode("utf-8", "replace"))
        return {"path": relative, **summary}


class KernelVmStatus(BaseSkill):
    name = "kernel_vm_status"
    description = "Report QEMU/KVM availability and host resources for the local isolated-VM repro workflow. Inspection only; boots nothing. Reports when KVM acceleration is unavailable."
    category = "kernel"
    timeout_seconds = 10
    output_properties = {"qemu": {"type": "object"}, "kvm": {"type": "object"}, "resources": {"type": "object"}, "disk_free_gb": {"type": ["number", "null"]}, "limitation": {"type": ["string", "null"]}}
    output_required = ("qemu", "kvm", "resources")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}, "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        return qemu.status(str(context.policy.workspace_roots[0]))
