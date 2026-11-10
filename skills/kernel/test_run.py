"""Approval-gated local test runner for the isolated-VM repro workflow.

Safety design (see SECURITY.md and the kernelCTF scope rules):

- CLI-only: never offered to or callable by the LLM.
- Requires one-use approval bound to the exact arguments.
- Runs ONLY a researcher-provided harness script that lives inside an authorized
  workspace (e.g. a reviewed `run-local.sh` that drives QEMU). It never runs
  model-generated code, never runs a shell string, and never fuzzes the host
  kernel.
- Refuses to run unless VM isolation is explicitly confirmed by the caller. WSL
  alone is not treated as a sandbox.
- Bounded wall-clock timeout plus best-effort CPU/address-space rlimits, and
  bounded captured output. Without approval or isolation, it only returns a
  prerequisite report and executes nothing.
"""
from __future__ import annotations

import asyncio
import os
import resource
from pathlib import Path
from typing import Any

from skills.base import BaseSkill, SkillContext, SkillError
from security.filesystem import open_parent
from adapters import qemu


def _rlimit_preexec(cpu_seconds: int, address_space_bytes: int):
    def _apply() -> None:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 2))
        except (ValueError, OSError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_AS, (address_space_bytes, address_space_bytes))
        except (ValueError, OSError):
            pass
        try:
            os.setsid()
        except OSError:
            pass
    return _apply


class KernelTestRun(BaseSkill):
    name = "kernel_test_run"
    description = "Run an approved, researcher-provided test harness in an isolated VM for local crash reproduction. CLI-only, approval-gated, refuses host execution and model-generated code."
    category = "kernel"
    cli_only = True
    mutating = True
    requires_approval = True
    timeout_seconds = 1800
    output_properties = {"executed": {"type": "boolean"}, "harness": {"type": ["string", "null"]}, "prerequisites": {"type": "object"}, "returncode": {"type": ["integer", "null"]}, "stdout": {"type": "string"}, "stderr": {"type": "string"}, "timed_out": {"type": "boolean"}, "note": {"type": "string"}}
    output_required = ("executed", "prerequisites", "note")

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {
            "harness": {"type": "string", "description": "Path (within workspace) to a reviewed executable test harness that drives an isolated VM."},
            "args": {"type": "array", "items": {"type": "string", "maxLength": 256}, "maxItems": 32, "default": []},
            "isolation_confirmed": {"type": "boolean", "default": False, "description": "Caller asserts the harness runs the test in an isolated VM, not on the host kernel."},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 1800, "default": 600},
            "cpu_seconds": {"type": "integer", "minimum": 1, "maximum": 1800, "default": 300},
            "memory_mb": {"type": "integer", "minimum": 64, "maximum": 8192, "default": 2048},
        }, "required": ["harness"], "additionalProperties": False}

    def _prereqs(self) -> dict:
        vm = qemu.status()
        return {"qemu_available": vm["qemu"]["available"], "kvm_accelerated": vm["kvm"]["accelerated"], "limitation": vm["limitation"]}

    def preview(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        return {"harness": arguments.get("harness"), "args": arguments.get("args", []), "isolation_confirmed": arguments.get("isolation_confirmed", False), "prerequisites": self._prereqs()}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        prereqs = self._prereqs()
        if not arguments.get("isolation_confirmed", False):
            return {"executed": False, "harness": arguments.get("harness"), "prerequisites": prereqs, "returncode": None, "stdout": "", "stderr": "", "timed_out": False,
                    "note": "VM isolation was not confirmed. Re-run with isolation_confirmed=true only when the harness drives an isolated VM (never the host kernel). Nothing was executed."}
        # Validate the harness is a regular, executable file inside the workspace.
        fd, root, name, relative = open_parent(context.policy, arguments["harness"])
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            import stat as _stat
            if not _stat.S_ISREG(st.st_mode):
                raise SkillError("Harness must be a regular file (no symlinks)")
            harness_abs = str(root.joinpath(*Path(relative).parts))
            if not os.access(harness_abs, os.X_OK):
                raise SkillError(f"Harness is not executable: {relative}")
        finally:
            os.close(fd)
        if not prereqs["qemu_available"]:
            raise SkillError("No QEMU system emulator available; cannot run an isolated repro. Nothing was executed.")
        timeout = min(int(arguments.get("timeout_seconds", 600)), int(self.timeout_seconds))
        cpu_seconds = int(arguments.get("cpu_seconds", 300))
        mem_bytes = int(arguments.get("memory_mb", 2048)) * 1024 * 1024
        argv = [harness_abs, *[str(a) for a in arguments.get("args", [])]]
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            cwd=str(root), preexec_fn=_rlimit_preexec(cpu_seconds, mem_bytes),
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(root)},
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, TimeoutError):
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), 9)
            except (ProcessLookupError, OSError):
                proc.kill()
            stdout, stderr = b"", b""
        cap = 32768
        return {"executed": True, "harness": relative, "prerequisites": prereqs, "returncode": proc.returncode,
                "stdout": stdout[:cap].decode("utf-8", "replace"), "stderr": stderr[:cap].decode("utf-8", "replace"),
                "timed_out": timed_out, "note": "Harness executed under bounded CPU/memory/time in the researcher's isolated-VM wrapper."}
