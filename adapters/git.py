"""Read-only git access to a local, authorized kernel checkout.

Every operation runs `git` with `--no-pager`, against a tree that has already
been validated to live inside an authorized workspace root. Output is bounded
and each call is time-limited. Nothing here writes to the repository, fetches
from a remote, or runs hooks.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from core.policy import Policy
from security.filesystem import open_dir

_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
# git refspec / revision: conservative allowlist to keep it an argument, not a shell.
_REV_RE = re.compile(r"^[0-9A-Za-z._/\-^~]{1,200}$")


class GitError(RuntimeError):
    pass


def _validate_rev(rev: str) -> str:
    rev = rev.strip()
    if not rev or not _REV_RE.match(rev) or rev.startswith("-"):
        raise GitError(f"Invalid git revision: {rev!r}")
    if ".." in rev and not re.match(r"^[0-9A-Za-z._/\-^~]+\.\.[0-9A-Za-z._/\-^~]+$", rev):
        raise GitError(f"Invalid revision range: {rev!r}")
    return rev


def _validate_tree(policy: Policy, tree: str) -> Path:
    import os
    fd, root, parts, _ = open_dir(policy, tree)
    os.close(fd)
    resolved = root.joinpath(*parts)
    if not (resolved / ".git").exists():
        raise GitError(f"Not a git checkout (no .git): {resolved}")
    return resolved


async def _run(tree: Path, args: list[str], *, timeout: float, max_bytes: int) -> str:
    proc = await asyncio.create_subprocess_exec(
        "git", "-C", str(tree), "--no-pager", *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(tree)},
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError) as exc:
        proc.kill()
        raise GitError("git command timed out") from exc
    if proc.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        raise GitError(f"git failed: {detail[0][:200]}")
    text = stdout[:max_bytes].decode("utf-8", "replace")
    return text


async def head(policy: Policy, tree: str, *, timeout: float = 15) -> dict:
    root = _validate_tree(policy, tree)
    sha = (await _run(root, ["rev-parse", "HEAD"], timeout=timeout, max_bytes=128)).strip()
    desc = (await _run(root, ["describe", "--tags", "--always", "--dirty"], timeout=timeout, max_bytes=256)).strip()
    return {"tree": str(root), "head": sha, "describe": desc}


async def show(policy: Policy, tree: str, rev: str, *, timeout: float = 20, max_bytes: int = 200_000, stat_only: bool = False) -> str:
    root = _validate_tree(policy, tree)
    rev = _validate_rev(rev)
    args = ["show", "--no-color"]
    if stat_only:
        args.append("--stat")
    args.append(rev)
    return await _run(root, args, timeout=timeout, max_bytes=max_bytes)


async def diff(policy: Policy, tree: str, base: str, target: str, *, path: str | None = None, timeout: float = 25, max_bytes: int = 300_000, stat_only: bool = False) -> str:
    root = _validate_tree(policy, tree)
    base, target = _validate_rev(base), _validate_rev(target)
    args = ["diff", "--no-color"]
    if stat_only:
        args.append("--stat")
    args.append(f"{base}..{target}")
    if path:
        if ".." in Path(path).parts or Path(path).is_absolute():
            raise GitError("diff path must be relative and within the tree")
        args += ["--", path]
    return await _run(root, args, timeout=timeout, max_bytes=max_bytes)


async def grep_commits(policy: Policy, tree: str, query: str, *, count: int = 40, timeout: float = 20, max_bytes: int = 100_000) -> list[dict]:
    """Search commit *messages* for a term (git log --grep). Read-only."""
    root = _validate_tree(policy, tree)
    query = query.strip()
    if not query or len(query) > 128 or any(ord(c) < 32 for c in query):
        raise GitError(f"Invalid grep query: {query!r}")
    count = max(1, min(int(count), 200))
    fmt = "%H%x1f%s"
    out = await _run(root, ["log", f"-n{count}", "--grep", query, "-i", f"--pretty=format:{fmt}", "HEAD"], timeout=timeout, max_bytes=max_bytes)
    commits = []
    for line in out.splitlines():
        fields = line.split("\x1f")
        if len(fields) == 2:
            commits.append({"commit": fields[0], "subject": fields[1][:300]})
    return commits


async def log(policy: Policy, tree: str, rev: str = "HEAD", *, count: int = 20, path: str | None = None, timeout: float = 20, max_bytes: int = 100_000) -> list[dict]:
    root = _validate_tree(policy, tree)
    rev = _validate_rev(rev)
    count = max(1, min(int(count), 200))
    fmt = "%H%x1f%an%x1f%ad%x1f%s"
    args = ["log", f"-n{count}", f"--pretty=format:{fmt}", "--date=short", rev]
    if path:
        if ".." in Path(path).parts or Path(path).is_absolute():
            raise GitError("log path must be relative and within the tree")
        args += ["--", path]
    out = await _run(root, args, timeout=timeout, max_bytes=max_bytes)
    commits = []
    for line in out.splitlines():
        fields = line.split("\x1f")
        if len(fields) == 4:
            commits.append({"commit": fields[0], "author": fields[1], "date": fields[2], "subject": fields[3][:300]})
    return commits
