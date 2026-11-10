"""Crash-novelty triage workflow.

Given an UNTRUSTED crash log, this:

1. stores the original evidence immutably and indexes its signature;
2. parses it (KASAN/KCSAN/Oops);
3. correlates against local *patch info* — the kernel git history — to see if an
   upstream commit already fixes the faulting area (a 1-day indicator);
4. checks the known-issue store and the local crash index for duplicates;
5. renders a verdict: if the crash is already-known (duplicate or 1-day), it
   recommends continuing the search; if it is novel, it records a candidate
   finding (a hypothesis) and drafts a report.

Offline-safe: the only external-ish lookup is the LOCAL git tree. Fetching
kernelCTF accepted-submission info and upstream patch metadata from the network
is an Online-phase action (`setup docs`); results are recorded into the
known-issue store and then used here offline.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from adapters import git, kasan, kcsan
from core.known_issues import KnownIssuesStore, CrashIndex, novelty_verdict
from core.findings import FindingsStore, new_finding

_FIX_HINT = re.compile(r"\b(fix|use-after-free|uaf|double.?free|out.?of.?bounds|oob|overflow|race|leak|CVE-\d{4}-\d+)\b", re.I)


def parse_crash(raw: str) -> dict:
    return kcsan.parse_report(raw) if "KCSAN" in raw else kasan.parse_report(raw)


async def correlate_patches(policy, tree: str | None, parsed: dict, *, max_commits: int = 40) -> list[dict]:
    """Look for an upstream commit in the local tree that appears to fix this area."""
    if not tree:
        return []
    fault = (parsed.get("fault_site") or "")
    symbol = fault.split("+")[0].strip()
    if not symbol or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        return []
    try:
        commits = await git.grep_commits(policy, tree, symbol, count=max_commits)
    except git.GitError:
        return []
    return [c for c in commits if _FIX_HINT.search(c["subject"])][:10]


def _next_finding_id(store: FindingsStore) -> str:
    n = 0
    for f in store.list():
        m = re.match(r"KERNEL-LOCAL-(\d+)$", f.get("finding_id", ""))
        if m:
            n = max(n, int(m.group(1)))
    return f"KERNEL-LOCAL-{n + 1:04d}"


def _draft_report(root: Path, finding: dict, parsed: dict, verdict: dict) -> Path:
    reports = Path(root) / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    dest = reports / f"{finding['finding_id']}.md"
    frames = "\n".join(f"  - {f['symbol']}" + (f" ({f.get('source')})" if f.get("source") else "") for f in parsed.get("frames", [])[:8])
    lines = [
        f"# {finding['finding_id']} — novel crash candidate (hypothesis)",
        "",
        f"_Drafted {date.today().isoformat()}. This is a HYPOTHESIS until reproduced in an isolated VM._",
        "",
        "## Classification",
        f"- Bug class: {parsed.get('bug_class')}",
        f"- Fault site: {parsed.get('fault_site')}",
        f"- Signature: {parsed.get('signature')}",
        f"- Access: {parsed.get('access')}",
        "",
        "## Novelty",
        f"- Verdict: {'NOVEL' if verdict['novel'] else 'KNOWN'}",
        f"- {verdict['recommendation']}",
        "",
        "## Stack (normalized, untrusted)",
        frames or "  (no frames parsed)",
        "",
        "## Next steps",
        "- Localize the faulting code from source and cite path:line.",
        "- Confirm reachability on the target instance.",
        "- Reproduce in an isolated VM, then set validation.status=reproduced.",
        "",
        "> Triage only. No exploit code is included.",
    ]
    dest.write_text("\n".join(lines) + "\n")
    return dest


async def run_triage(agent, raw: str, *, source: str | None = None) -> dict:
    policy = agent.policy
    root = policy.workspace_roots[0]
    findings = agent.findings
    known = KnownIssuesStore(root)
    index = CrashIndex(root)

    stored = findings.store_crash_evidence(raw)
    parsed = parse_crash(raw)
    # Check for a prior occurrence of this signature BEFORE recording this one.
    prior = index.prior_matches(parsed)
    index.record(parsed, stored["sha256"])

    known_hits = known.match(parsed)
    patch_hits = await correlate_patches(policy, source, parsed)
    verdict = novelty_verdict(parsed, known_hits=known_hits, prior_crashes=prior, patch_hits=patch_hits)

    result = {"evidence": stored, "parsed": parsed, "verdict": verdict}
    if verdict["novel"]:
        fid = _next_finding_id(findings)
        finding = new_finding(
            finding_id=fid, bug_class=parsed.get("bug_class", "unknown"),
            subsystem="", source_file=(parsed.get("frames") or [{}])[0].get("source", ""),
            function=(parsed.get("fault_site") or "").split("+")[0],
            reasoning=f"Novel crash candidate from triage. {verdict['recommendation']}",
            evidence=[f"crash:{stored['sha256']}", f"signature:{parsed.get('signature')}"],
            confidence="low",
        )
        findings.add(finding)
        report_path = _draft_report(root, finding, parsed, verdict)
        result["finding_id"] = fid
        result["report"] = str(report_path)
        result["action"] = "recorded_finding_and_drafted_report"
    else:
        result["action"] = "known_crash_keep_searching"
    return result
