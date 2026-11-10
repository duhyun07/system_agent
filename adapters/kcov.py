"""Read a KCOV / fuzzing coverage summary from the local workspace.

Reads a text or JSON coverage summary that the researcher's harness already
produced. It does not instrument, build, or run anything. Supported shapes:

- JSON with numeric fields (e.g. {"pcs": 1234, "edges": 567}) -> returned as-is
  under "metrics".
- Plain text with "key: number" or "key number" lines -> parsed into metrics.
"""
from __future__ import annotations

import json
import re

_KV = re.compile(r"^\s*([A-Za-z][\w .%-]*?)\s*[:=]?\s*([0-9][0-9,._]*)\s*$")


def parse_summary(text: str, *, max_lines: int = 2000) -> dict:
    text = text.strip()
    if text[:1] in "{[":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                metrics = {k: v for k, v in data.items() if isinstance(v, (int, float))}
                return {"format": "json", "metrics": metrics, "raw_keys": sorted(data)}
        except ValueError:
            pass
    metrics: dict[str, float] = {}
    for line in text.splitlines()[:max_lines]:
        m = _KV.match(line)
        if m:
            num = m.group(2).replace(",", "").replace("_", "")
            try:
                metrics[m.group(1).strip().lower()] = float(num) if "." in num else int(num)
            except ValueError:
                continue
    return {"format": "text", "metrics": metrics, "raw_keys": sorted(metrics)}
