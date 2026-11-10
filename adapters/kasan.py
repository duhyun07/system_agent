"""Parse Linux kernel crash reports (KASAN / Oops / panic / general BUG).

Input is UNTRUSTED text captured from a VM console or dmesg. The parser only
extracts structure (bug class, fault address, access type, call stack frames)
and normalizes a signature for deduplication. It never executes anything and
never treats the log's contents as instructions.

KCSAN reports are handled by :mod:`adapters.kcsan`, which reuses the frame and
signature helpers here.
"""
from __future__ import annotations

import hashlib
import re

# A kernel stack frame line, e.g. " kasan_report+0x1a/0x20" or
# " [<...>] do_thing+0x10/0x40 [module]" or with source "func (mm/slub.c:123)".
_FRAME_RE = re.compile(
    r"""^\s*
        (?:\[<[0-9a-fA-Fx]+>\]\s*)?          # optional [<addr>]
        (?:\?\s*)?                            # optional unreliable '?'
        (?P<sym>[A-Za-z_][A-Za-z0-9_.]*)      # symbol name
        (?:\+0x[0-9a-fA-F]+/0x[0-9a-fA-F]+)?  # +off/size
        (?:\s*\[(?P<mod>[\w-]+)\])?           # optional [module]
        (?:\s*\((?P<src>[\w./-]+:\d+)\))?     # optional (file:line)
        \s*$""",
    re.VERBOSE,
)

_KASAN_BUG_RE = re.compile(r"BUG:\s*KASAN:\s*(?P<kind>[\w-]+)\s+in\s+(?P<where>\S+)", re.I)
_ACCESS_RE = re.compile(r"(?P<rw>Read|Write)\s+of\s+size\s+(?P<size>\d+)\s+at\s+addr\s+(?P<addr>[0-9a-fx]+)", re.I)
_GENERIC_BUG_RE = re.compile(r"(?:BUG|Oops|kernel BUG|general protection fault|Unable to handle kernel|WARNING):?\s*(?P<rest>.*)", re.I)
_CALL_TRACE_START = re.compile(r"^\s*(Call Trace|Call trace):", re.I)
_RIP_RE = re.compile(r"RIP:\s*\S+\s+(?P<sym>[A-Za-z_][\w.]*)")

# Non-symbol tokens that sometimes match the frame regex but are not frames.
_FRAME_STOPWORDS = frozenset({
    "Read", "Write", "Memory", "The", "Call", "Allocated", "Freed", "Last",
    "CPU", "Hardware", "RIP", "RSP", "Code", "RAX", "RBX", "Modules",
})


def _clean_frames(lines: list[str], *, limit: int = 32) -> list[dict]:
    frames: list[dict] = []
    for line in lines:
        m = _FRAME_RE.match(line)
        if not m:
            continue
        sym = m.group("sym")
        if sym in _FRAME_STOPWORDS or sym.isupper() and len(sym) <= 4:
            continue
        frame = {"symbol": sym}
        if m.group("src"):
            frame["source"] = m.group("src")
        if m.group("mod"):
            frame["module"] = m.group("mod")
        frames.append(frame)
        if len(frames) >= limit:
            break
    return frames


def _signature(bug_class: str, top_symbols: list[str]) -> str:
    """Stable signature from bug class + top 3 frame symbols (offsets stripped)."""
    key = bug_class + "|" + "|".join(top_symbols[:3])
    return "crash:" + hashlib.sha256(key.encode()).hexdigest()[:16]


def parse_report(text: str, *, max_lines: int = 4000) -> dict:
    """Parse a single kernel crash report into a structured dict."""
    lines = text.splitlines()[:max_lines]
    joined = "\n".join(lines)

    bug_class = "unknown"
    fault_site = None
    access = None

    km = _KASAN_BUG_RE.search(joined)
    if km:
        bug_class = "kasan-" + km.group("kind").lower()
        fault_site = km.group("where")
    else:
        gm = _GENERIC_BUG_RE.search(joined)
        if gm:
            head = gm.group(0).lower()
            if "null" in head or "unable to handle kernel null" in head:
                bug_class = "null-deref"
            elif "general protection" in head:
                bug_class = "gpf"
            elif "kernel bug" in head or head.startswith("bug"):
                bug_class = "bug"
            elif "warning" in head:
                bug_class = "warning"
            elif "oops" in head:
                bug_class = "oops"

    am = _ACCESS_RE.search(joined)
    if am:
        access = {"type": am.group("rw").lower(), "size": int(am.group("size")), "addr": am.group("addr")}

    # Collect frames from the first Call Trace block (fall back to whole text).
    trace_lines: list[str] = []
    collecting = False
    for line in lines:
        if _CALL_TRACE_START.search(line):
            collecting = True
            continue
        if collecting:
            if not line.strip() or line.strip().startswith(("---", "===", "RIP:", "Code:")):
                if trace_lines:
                    break
                continue
            trace_lines.append(line)
    frames = _clean_frames(trace_lines or lines)

    if fault_site is None:
        rm = _RIP_RE.search(joined)
        if rm:
            fault_site = rm.group("sym")
        elif frames:
            fault_site = frames[0]["symbol"]

    top_symbols = [f["symbol"] for f in frames]
    if fault_site and (not top_symbols or top_symbols[0] != fault_site.split("+")[0]):
        top_symbols = [fault_site.split("+")[0]] + top_symbols

    return {
        "bug_class": bug_class,
        "fault_site": fault_site,
        "access": access,
        "frames": frames,
        "frame_count": len(frames),
        "signature": _signature(bug_class, top_symbols),
        "truncated": len(text.splitlines()) > max_lines,
    }
