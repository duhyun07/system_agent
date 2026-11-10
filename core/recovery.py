from __future__ import annotations

from skills.base import SkillResult


def recovery_hint(name: str, arguments: dict, result: SkillResult) -> str | None:
    """Return a concrete corrective next step for a failed or unproductive tool call.

    The hint is attached to the tool result the model reads next, so a weak local
    model can recover its own strategy instead of repeating the same failing call.
    Returns None when the call succeeded and produced usable output.
    """
    if not result.ok:
        error = result.error or ""
        low = error.lower()
        if "filenotfound" in low or "no such file" in low:
            return ("The path does not exist. Call list_dir on the parent directory or search_files to "
                    "locate the real path before retrying; do not guess another filename.")
        if "not allowlisted" in low or "domain is not" in low:
            return ("That domain is not allowlisted for fetch. Use web_search to find a source, or fetch an "
                    "allowlisted domain such as kernel.org, lwn.net, github.com, or nvd.nist.gov.")
        if "path outside" in low or "traversal" in low:
            return ("The path is outside the task source root. Use '.' for the source root and a relative path "
                    "within it.")
        if "was not offered" in low or "unavailable" in low:
            return f"The {name} skill is not available for this task. Use one of the offered skills instead."
        short = error.split("\n", 1)[0][:200]
        return f"The {name} call failed ({short}). Fix the arguments or use a different skill; do not repeat the same call."

    output = result.output or {}
    if name == "search_files" and not output.get("paths"):
        return ("search_files matched nothing. It matches file BASENAMES by glob only — not directories and not "
                "substrings. To list a directory use list_dir (e.g. path='mm'); to find files use a glob like "
                "'*.c' or 'kasan*'; to find code by content use grep. A bare word like 'mm' will never match the "
                "mm/ directory.")
    if name == "grep" and not output.get("matches"):
        return ("grep found no matches. Broaden the pattern or verify the root path with list_dir; the symbol may "
                "live in a different directory.")
    if name == "list_dir" and not output.get("entries"):
        return "list_dir returned no entries. Verify the directory path; use search_files to locate it."
    if name == "web_search" and not output.get("results"):
        return "web_search returned no results. Rephrase the query with different or fewer keywords."
    if name == "fetch":
        status = output.get("status_code")
        if isinstance(status, int) and status >= 400:
            return f"fetch returned HTTP {status}. Try a different URL or use web_search to find a working source."
    return None
