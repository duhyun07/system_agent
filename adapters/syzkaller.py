"""Inspect an existing, authorized syzkaller work directory. Read-only.

This adapter NEVER launches syzkaller, never generates or executes programs,
and never fuzzes the host kernel. It only summarizes artifacts a researcher's
own authorized, isolated fuzzing run already produced: the presence of the
syz-manager binary, and counts of corpus and crash entries under a workdir.

Launching bounded fuzzing in an isolated VM is out of scope for this platform
in the current environment (syz-manager is not installed and host-kernel
fuzzing is prohibited); this is documented as a limitation.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from core.policy import Policy
from security.filesystem import open_dir


def manager_available() -> dict:
    path = shutil.which("syz-manager")
    return {"syz_manager": path, "available": bool(path)}


def workdir_summary(policy: Policy, workdir: str, *, max_entries: int = 100000) -> dict:
    fd, root, parts, _ = open_dir(policy, workdir)
    os.close(fd)
    base = root.joinpath(*parts)
    crashes_dir = base / "crashes"
    corpus_db = base / "corpus.db"
    crash_count = 0
    crash_signatures: list[str] = []
    if crashes_dir.is_dir():
        for entry in sorted(crashes_dir.iterdir())[:max_entries]:
            if entry.is_dir():
                crash_count += 1
                desc = entry / "description"
                if desc.is_file():
                    try:
                        crash_signatures.append(desc.read_text(errors="replace").strip()[:200])
                    except OSError:
                        pass
    return {
        "workdir": str(base),
        "has_corpus_db": corpus_db.is_file(),
        "corpus_db_bytes": corpus_db.stat().st_size if corpus_db.is_file() else 0,
        "crash_count": crash_count,
        "crash_descriptions": crash_signatures[:50],
        "note": "Read-only summary of an existing authorized run. This platform does not launch fuzzing.",
    }
