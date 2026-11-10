"""Deterministic environment inspection and the offline-research readiness gate.

No LLM, no network. These checks power `doctor`, `setup verify`, `research
prepare`, and the pre-flight for `research start --offline`. They report the
real state of the host and refuse to enter offline research when mandatory
prerequisites are missing, explaining how to resolve each one.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import socket
from pathlib import Path
from urllib.parse import urlsplit

from core.policy import Policy
from adapters import qemu

# Toolchain used for reading/analyzing (and, where the user chooses, building) kernels.
ANALYSIS_TOOLS = ("git", "gdb")
BUILD_TOOLS = ("gcc", "clang", "ld.lld", "make", "flex", "bison", "bc", "pahole")
PY_DEPS = ("httpx", "openai", "yaml", "jsonschema", "regex")


def _which_map(names) -> dict:
    return {name: shutil.which(name) for name in names}


def ollama_status(policy: Policy, *, timeout: float = 1.0) -> dict:
    parsed = urlsplit(policy.ollama_url)
    out = {"url": policy.ollama_url, "reachable": False, "status": "unreachable", "models": [], "default_model": policy.ollama_model, "default_model_present": False}
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=timeout):
            out["status"] = "reachable"
            out["reachable"] = True
    except PermissionError:
        out["status"] = "socket_denied"
        return out
    except (ConnectionRefusedError, TimeoutError, OSError, TypeError, ValueError):
        return out
    # Reachable: best-effort model listing via the tags endpoint.
    try:
        import httpx
        resp = httpx.get(policy.ollama_url.rstrip("/") + "/api/tags", timeout=timeout + 1, trust_env=False)
        if resp.status_code == 200:
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            out["models"] = models
            out["default_model_present"] = any(m == policy.ollama_model or m.split(":")[0] == policy.ollama_model.split(":")[0] for m in models)
    except Exception:
        pass
    return out


def inspect(policy: Policy) -> dict:
    """A full, deterministic snapshot of the environment."""
    vm = qemu.status(str(policy.workspace_roots[0]))
    return {
        "python_deps": {name: importlib.util.find_spec(name) is not None for name in PY_DEPS},
        "analysis_tools": {k: bool(v) for k, v in _which_map(ANALYSIS_TOOLS).items()},
        "build_tools": {k: bool(v) for k, v in _which_map(BUILD_TOOLS).items()},
        "qemu": vm["qemu"],
        "kvm": vm["kvm"],
        "resources": vm["resources"],
        "disk_free_gb": vm["disk_free_gb"],
        "ollama": ollama_status(policy),
        "workspace_roots": [str(p) for p in policy.workspace_roots],
        "missing_workspace_roots": [str(p) for p in policy.workspace_roots if not p.is_dir()],
        "kvm_limitation": vm["limitation"],
    }


def is_kernel_tree(path: Path) -> bool:
    return (path / "Makefile").is_file() and (path / "Kconfig").is_file() and (path / "include" / "linux").is_dir()


def kernel_trees(policy: Policy) -> list[str]:
    return [str(p) for p in policy.workspace_roots if p.is_dir() and is_kernel_tree(p)]


def target_manifest_path(policy: Policy) -> Path:
    return policy.workspace_roots[0] / "research" / "kernel" / "target-manifest.json"


def load_target_manifest(policy: Policy) -> dict | None:
    path = target_manifest_path(policy)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def offline_readiness(policy: Policy) -> dict:
    """Gate for entering OFFLINE_RESEARCH. Returns {ready, checks, blockers, advisories}."""
    env = inspect(policy)
    checks: list[dict] = []
    blockers: list[str] = []
    advisories: list[str] = []

    def record(name: str, ok: bool, *, blocking: bool, detail: str, fix: str = "") -> None:
        checks.append({"check": name, "ok": ok, "blocking": blocking, "detail": detail, "fix": fix})
        if not ok:
            (blockers if blocking else advisories).append(f"{name}: {detail}" + (f" Fix: {fix}" if fix else ""))

    trees = kernel_trees(policy)
    record("local_kernel_source", bool(trees), blocking=True,
           detail=f"{len(trees)} authorized kernel tree(s) found" if trees else "No authorized kernel checkout found in workspace_roots",
           fix="Add an authorized Linux checkout (with Makefile/Kconfig/include/linux) to workspace_roots in configs/offline.yaml")

    manifest = load_target_manifest(policy)
    record("target_configuration", manifest is not None, blocking=True,
           detail="Target manifest recorded" if manifest else "No selected target configuration recorded",
           fix="Run 'system-agent setup docs' then 'system-agent setup target select <instance>' to record the current target from official docs")

    oll = env["ollama"]
    record("ollama_reachable", oll["reachable"], blocking=True, detail=f"Ollama {oll['status']} at {oll['url']}",
           fix="Start 'ollama serve' and verify with 'system-agent doctor'")
    record("local_model", oll["default_model_present"], blocking=oll["reachable"],
           detail=f"Model {oll['default_model']} {'present' if oll['default_model_present'] else 'not found'}",
           fix=f"Run 'ollama pull {oll['default_model']}'")

    read_only_ok = all(env["analysis_tools"].values())
    record("analysis_tools", read_only_ok, blocking=False,
           detail="read-only analysis tools present" if read_only_ok else f"missing: {[k for k,v in env['analysis_tools'].items() if not v]}",
           fix="Install git and gdb for commit-diff and debugging helpers")

    mem = env["resources"].get("available_memory_gb")
    mem_ok = mem is None or mem >= 1.0
    record("memory", mem_ok, blocking=False, detail=f"{mem} GiB available" if mem is not None else "unknown",
           fix="Free memory before loading the local model and running builds")
    disk = env["disk_free_gb"]
    disk_ok = disk is None or disk >= 20.0
    record("disk", disk_ok, blocking=False, detail=f"{disk} GiB free" if disk is not None else "unknown",
           fix="Free disk space; kernel source and builds are large")

    # Offline research runs with network skills disabled by design (Phase B isolation).
    record("network_blocked_for_research", True, blocking=False,
           detail="Offline research runs with all network skills disabled, independent of the mode allowlist")

    if env["kvm_limitation"]:
        advisories.append("kvm: " + env["kvm_limitation"])

    ready = not blockers
    return {"ready": ready, "checks": checks, "blockers": blockers, "advisories": advisories,
            "kernel_trees": trees, "target_manifest": manifest, "environment": env}
