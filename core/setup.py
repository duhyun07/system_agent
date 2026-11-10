"""Target selection and manifest recording for the Online setup phase.

`setup target select` records which authorized kernelCTF instance the researcher
is targeting, together with the local source tree used for analysis. The exact
kernel version, commit, and config checksum are confirmed from the official
release metadata (via `setup docs` / the online documentation agent and the
official metadata.json); this module records what is known and marks the rest as
unconfirmed rather than inventing it.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from core.policy import Policy
from core.programs import Program
from security.filesystem import atomic_write, checked_path, open_dir


def target_manifest(program: Program, instance: str, *, source: str, extra: dict | None = None) -> dict:
    if instance not in program.instances:
        known = ", ".join(program.instances) or "(none configured)"
        raise ValueError(f"Unknown instance '{instance}' for {program.key}. Configured instances: {known}")
    spec = program.instances.get(instance, {})
    manifest = {
        "program": program.key,
        "instance": instance,
        "kernel": spec.get("kernel", ""),
        "description": spec.get("description", ""),
        "config_focus": list(spec.get("config_focus", []) or []),
        "source_tree": source,
        "official_rules": program.links.get("official_rules", ""),
        "release_page": program.artifacts.get("release_page", ""),
        # These must be confirmed from the official release metadata, not guessed.
        "kernel_version": (extra or {}).get("kernel_version", "UNCONFIRMED — read from official metadata.json"),
        "kernel_commit": (extra or {}).get("kernel_commit", "UNCONFIRMED — read from official metadata.json"),
        "config_sha256": (extra or {}).get("config_sha256", ""),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "note": "Recorded for offline research scoping. Confirm exact version/commit/config against the official release before relying on them.",
    }
    return manifest


def record_target(policy: Policy, program: Program, instance: str, *, source: str, extra: dict | None = None) -> tuple[Path, dict]:
    # Validate the source tree is an authorized workspace directory.
    fd, root, parts, _ = open_dir(policy, source)
    os.close(fd)
    source_abs = str(root.joinpath(*parts))
    manifest = target_manifest(program, instance, source=source_abs, extra=extra)
    rel = "research/kernel/target-manifest.json"
    dest_root, dest_parts, _ = checked_path(policy, rel)
    os.makedirs(dest_root.joinpath(*dest_parts[:-1]), exist_ok=True)
    atomic_write(policy, rel, (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode(), overwrite=True)
    return dest_root.joinpath(*dest_parts), manifest
