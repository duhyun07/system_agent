from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path
from core.policy import Policy
from skills.base import SkillError


def checked_path(policy: Policy, value: str) -> tuple[Path, tuple[str, ...], str]:
    if not value or "\x00" in value:
        raise SkillError("Invalid path")
    raw = Path(value)
    if raw.is_absolute():
        matches = [root for root in policy.workspace_roots if raw == root or root in raw.parents]
        if not matches:
            raise SkillError("Path outside authorized workspaces; add the existing source root to workspace_roots in configs/<mode>.yaml")
        root = max(matches, key=lambda x: len(x.parts))
        parts = raw.relative_to(root).parts
    else:
        root = policy.workspace_roots[0]
        parts = raw.parts
    if any(part in ("..", "") for part in parts):
        raise SkillError("Path traversal rejected")
    sensitive_suffixes = (".pem", ".key", ".p12", ".pfx")
    if any(part in policy.ignored_dirs or part in policy.protected_names or part.startswith(".env") or part.lower().endswith(sensitive_suffixes) or part in (".ssh", ".kube", ".gnupg", ".npmrc", ".pypirc", ".netrc") for part in parts):
        raise SkillError("Protected path")
    return root, parts, str(Path(*parts)) if parts else "."


def open_dir(policy: Policy, value: str) -> tuple[int, Path, tuple[str, ...], str]:
    root, parts, relative = checked_path(policy, value)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, root, parts, relative
    except BaseException:
        os.close(fd)
        raise


def open_parent(policy: Policy, value: str) -> tuple[int, Path, str, str]:
    root, parts, relative = checked_path(policy, value)
    if not parts:
        raise SkillError("A file path is required")
    parent = str(Path(*parts[:-1])) if len(parts) > 1 else "."
    fd, _, _, _ = open_dir(policy, str(root / parent))
    return fd, root, parts[-1], relative


def read_bytes(policy: Policy, value: str) -> tuple[bytes, os.stat_result, str]:
    parent, _, name, relative = open_parent(policy, value)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SkillError("Regular file required")
            if info.st_size > policy.limits.max_read_bytes:
                raise SkillError("File exceeds read-size limit")
            chunks = bytearray()
            while True:
                chunk = os.read(fd, min(65536, policy.limits.max_read_bytes + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if len(chunks) > policy.limits.max_read_bytes:
                    raise SkillError("File exceeds read-size limit")
            return bytes(chunks), info, relative
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(policy: Policy, value: str, data: bytes, *, overwrite: bool, expected_sha256: str | None = None, preserve_mode: bool = False) -> tuple[str | None, str]:
    if len(data) > policy.limits.max_write_bytes:
        raise SkillError("Content exceeds write-size limit")
    parent, _, name, _ = open_parent(policy, value)
    temp_name = f".system-agent-{secrets.token_hex(12)}"
    temp_fd = None
    try:
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current and not stat.S_ISREG(current.st_mode):
            raise SkillError("Existing path is not a regular file")
        if current and not overwrite:
            raise SkillError("File already exists; overwrite is false")
        if expected_sha256 is not None:
            if not current:
                raise SkillError("Expected file does not exist")
            old, _, _ = read_bytes(policy, value)
            if sha256(old) != expected_sha256:
                raise SkillError("Stale file hash")
            before_hash = sha256(old)
        elif current:
            old, _, _ = read_bytes(policy, value)
            before_hash = sha256(old)
        else:
            before_hash = None
        temp_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(temp_fd, "wb", closefd=True) as handle:
            temp_fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if preserve_mode and current:
            os.chmod(temp_name, stat.S_IMODE(current.st_mode), dir_fd=parent, follow_symlinks=False)
        if overwrite:
            if expected_sha256 is not None:
                latest, _, _ = read_bytes(policy, value)
                if sha256(latest) != expected_sha256:
                    raise SkillError("File changed during edit")
            os.replace(temp_name, name, src_dir_fd=parent, dst_dir_fd=parent)
        else:
            os.link(temp_name, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temp_name, dir_fd=parent)
        os.fsync(parent)
        return before_hash, sha256(data)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)
