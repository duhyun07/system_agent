from __future__ import annotations

from pathlib import Path
from typing import Any

from skills.base import BaseSkill, SkillContext, SkillError
from security.filesystem import checked_path, open_dir


class KernelSkill(BaseSkill):
    """Base for kernelCTF source/analysis skills. Read-only by default.

    All of these operate on an authorized kernel checkout. The tree is taken from
    the `kernel` argument when given, otherwise from the task's source root. Every
    path is validated against the workspace sandbox (no traversal, no symlink
    escape, no protected names) before any I/O.
    """
    category = "kernel"
    mutating = False

    def _tree(self, arguments: dict[str, Any], context: SkillContext) -> Path:
        value = arguments.get("kernel")
        if not value:
            if context.source_root is not None:
                value = str(context.source_root)
            else:
                raise SkillError("No kernel tree given: pass 'kernel' or run within a research source root")
        import os
        fd, root, parts, _ = open_dir(context.policy, value)
        os.close(fd)
        return root.joinpath(*parts)

    def _subpath(self, tree: Path, context: SkillContext, rel: str | None) -> Path:
        """Resolve a relative path under the kernel tree, kept inside the sandbox."""
        if not rel or rel == ".":
            return tree
        raw = Path(rel)
        if raw.is_absolute() or ".." in raw.parts:
            raise SkillError("Path must be relative to the kernel tree and may not traverse upward")
        target = tree / raw
        # Re-validate the composed path against the workspace policy.
        checked_path(context.policy, str(target))
        return target
