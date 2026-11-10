"""Parse KCSAN (Kernel Concurrency Sanitizer) data-race reports.

Untrusted input. Extracts the two racing accesses (type, size, symbol) and a
normalized signature, reusing the frame/signature helpers from adapters.kasan.
"""
from __future__ import annotations

import re

from adapters.kasan import _clean_frames, _signature

_KCSAN_HEAD = re.compile(r"BUG:\s*KCSAN:\s*(?P<kind>.+?)\s+in\s+(?P<where>\S+)", re.I)
_RACE_ACCESS = re.compile(
    r"(?P<rw>read|write)(?:-marked)?\s+(?:to|of)\s+(?:size\s+)?(?P<size>\d+)?.*?\bin\s+(?P<sym>[A-Za-z_][\w.]*)",
    re.I,
)


def parse_report(text: str, *, max_lines: int = 4000) -> dict:
    lines = text.splitlines()[:max_lines]
    joined = "\n".join(lines)
    head = _KCSAN_HEAD.search(joined)
    kind = head.group("kind").strip().lower() if head else "data-race"
    where = head.group("where") if head else None
    accesses = []
    for m in _RACE_ACCESS.finditer(joined):
        accesses.append({"type": m.group("rw").lower(), "size": int(m.group("size")) if m.group("size") else None, "symbol": m.group("sym")})
        if len(accesses) >= 2:
            break
    frames = _clean_frames(lines)
    top = [where.split("+")[0]] if where else []
    top += [a["symbol"] for a in accesses]
    return {
        "bug_class": "kcsan-data-race",
        "race_kind": kind,
        "where": where,
        "accesses": accesses,
        "frames": frames,
        "frame_count": len(frames),
        "signature": _signature("kcsan-data-race", top or [f["symbol"] for f in frames]),
        "truncated": len(text.splitlines()) > max_lines,
    }
