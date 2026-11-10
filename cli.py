from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import sys
from pathlib import Path

from core.orchestrator import SystemAgent
from core.policy import Policy
from core.progress import ConsoleProgress, FileProgress
from skills.base import SkillError

RESEARCH_MODES = ("offline", "hybrid")  # modes whose research provider is local Ollama


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="system-agent", description="Local-first Linux kernel research platform for Google kernelCTF.")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Environment and provider health report")
    sub.add_parser("status", help="Workflow phase, mode, and offline-readiness summary")

    mode = sub.add_parser("mode", help="Show or set the provider mode")
    mode_sub = mode.add_subparsers(dest="action", required=True)
    mode_sub.add_parser("show")
    mode_sub.add_parser("set").add_argument("value", choices=("offline", "online", "hybrid"))

    models = sub.add_parser("models", help="Model provider roster and connectivity tests")
    models_sub = models.add_subparsers(dest="action", required=True)
    models_sub.add_parser("list")
    mtest = models_sub.add_parser("test")
    mtest.add_argument("--provider", choices=("ollama", "openai"), required=True)

    setup = sub.add_parser("setup", help="Online setup: documentation, target, dependencies, verification")
    setup_sub = setup.add_subparsers(dest="action", required=True)
    setup_sub.add_parser("docs", help="Retrieve/summarize official kernelCTF docs (Online)")
    setup_sub.add_parser("known-issues", help="Surface known/fixed kernelCTF bugs and patch info for the novelty check (Online)")
    target = setup_sub.add_parser("target")
    target_sub = target.add_subparsers(dest="target_action", required=True)
    target_sub.add_parser("list")
    tsel = target_sub.add_parser("select")
    tsel.add_argument("--instance", required=True, help="Target instance, e.g. lts, cos, mitigation")
    tsel.add_argument("--source", required=True, help="Authorized kernel checkout for analysis")
    tsel.add_argument("--program", default="kctf")
    setup_sub.add_parser("dependencies", help="Inspect installed dependencies and readiness")
    setup_sub.add_parser("kernel", help="Inspect authorized kernel source trees and build provenance")
    setup_sub.add_parser("qemu", help="Report QEMU/KVM status for the isolated-VM workflow")
    setup_sub.add_parser("verify", help="Verify the environment and advance toward offline readiness")

    research = sub.add_parser("research", help="Offline kernel research (Ollama only)")
    research_sub = research.add_subparsers(dest="action", required=True)
    research_sub.add_parser("prepare", help="Check offline-research prerequisites")
    rstart = research_sub.add_parser("start")
    rstart.add_argument("--offline", action="store_true", required=True, help="Enter the offline research phase")
    for name, default_task in (
        ("source", "Inspect the subsystem and identify security-relevant code with cited evidence."),
        ("memory", "Review allocation/free, refcounting, bounds and integer math for candidate memory-safety issues."),
        ("concurrency", "Review locking and shared state for candidate race conditions."),
        ("patches", "Compare recent commits for security-relevant changes and incomplete fixes."),
    ):
        r = research_sub.add_parser(name)
        r.add_argument("--subsystem", help="Subsystem/directory within the tree, e.g. mm or net/ipv4")
        r.add_argument("--source", help="Kernel tree (defaults to the recorded target's source tree)")
        r.add_argument("--task", default=default_task)

    crash = sub.add_parser("crash", help="Crash/sanitizer log triage")
    crash_sub = crash.add_subparsers(dest="action", required=True)
    canalyze = crash_sub.add_parser("analyze")
    canalyze.add_argument("--input", required=True, help="Path to a crash/sanitizer log (read as untrusted evidence)")
    ctriage = crash_sub.add_parser("triage", help="Judge novelty vs known issues/patches; draft a report if novel")
    ctriage.add_argument("--input", required=True)
    ctriage.add_argument("--source", help="Kernel git tree for patch correlation (defaults to the recorded target)")
    crash_sub.add_parser("list")
    cknown = crash_sub.add_parser("known", help="Known-issue registry used for novelty judgment")
    cknown_sub = cknown.add_subparsers(dest="known_action", required=True)
    cknown_sub.add_parser("list")
    kadd = cknown_sub.add_parser("add")
    kadd.add_argument("--signature")
    kadd.add_argument("--fault-site")
    kadd.add_argument("--fix-commit")
    kadd.add_argument("--cve")
    kadd.add_argument("--status", default="known", choices=("fixed", "submitted", "known"))
    kadd.add_argument("--note", default="")
    kadd.add_argument("--source", default="manual")

    findings = sub.add_parser("findings", help="Recorded candidate findings")
    findings_sub = findings.add_subparsers(dest="action", required=True)
    findings_sub.add_parser("list")
    findings_sub.add_parser("show").add_argument("finding_id")

    programs = sub.add_parser("programs", help="kernelCTF program profile")
    programs_sub = programs.add_subparsers(dest="action", required=True)
    programs_sub.add_parser("list")
    programs_sub.add_parser("show").add_argument("program")

    report = sub.add_parser("report", help="Draft a submission report")
    report_sub = report.add_subparsers(dest="action", required=True)
    report_sub.add_parser("template").add_argument("program")
    rbuild = report_sub.add_parser("build")
    rbuild.add_argument("program")
    rbuild.add_argument("--fields", default="{}")
    rbuild.add_argument("--fields-file")
    rgen = report_sub.add_parser("generate")
    rgen.add_argument("--program", default="kctf")
    rgen.add_argument("--finding", help="Finding ID to render (default: all recorded findings)")

    audit = sub.add_parser("audit", help="Inspect the skill audit log")
    audit_sub = audit.add_subparsers(dest="action", required=True)
    ashow = audit_sub.add_parser("show")
    ashow.add_argument("--task", help="Filter by task_id")
    ashow.add_argument("--limit", type=int, default=50)

    env = sub.add_parser("env", help="Scaffold a local kernelCTF repro/debug environment")
    env_sub = env.add_subparsers(dest="action", required=True)
    env_sub.add_parser("instances").add_argument("program")
    env_init = env_sub.add_parser("init")
    env_init.add_argument("program")
    env_init.add_argument("--instance", required=True)
    env_init.add_argument("--source", required=True)
    env_init.add_argument("--dest")
    env_init.add_argument("--force", action="store_true")

    # Low-level skill and direct-tool access (kept from the original CLI).
    skills = sub.add_parser("skills")
    skills_sub = skills.add_subparsers(dest="action", required=True)
    skills_sub.add_parser("list")
    skills_sub.add_parser("info").add_argument("name")
    preview = skills_sub.add_parser("approval-hash")
    preview.add_argument("name")
    preview.add_argument("arguments")
    run = skills_sub.add_parser("run")
    run.add_argument("name")
    run.add_argument("arguments")
    run.add_argument("--approve-sha256")
    read = sub.add_parser("read")
    read.add_argument("path")
    read.add_argument("--start-line", type=int)
    read.add_argument("--end-line", type=int)
    ls = sub.add_parser("ls")
    ls.add_argument("path", nargs="?", default=".")
    ls.add_argument("--recursive", action="store_true")
    search = sub.add_parser("search")
    search.add_argument("pattern")
    search.add_argument("--path", default=".")
    search.add_argument("--regex", action="store_true")
    fetch = sub.add_parser("fetch")
    fetch.add_argument("url")
    web = sub.add_parser("web-search")
    web.add_argument("query")
    cloud = sub.add_parser("cloud", help="Explicit Hybrid cloud task; exact payload approval required")
    cloud.add_argument("action", choices=("approval-hash", "run"))
    cloud.add_argument("task")
    cloud.add_argument("--approve-sha256")
    return p


@contextlib.asynccontextmanager
async def key_toggle(progress):
    """While active, a space keypress toggles the live thinking view. POSIX TTY only."""
    toggler = getattr(progress, "toggle_thinking", None)
    try:
        fd = sys.stdin.fileno() if sys.stdin and sys.stdin.isatty() else None
    except (ValueError, OSError):
        fd = None
    if toggler is None or fd is None or os.name != "posix":
        yield
        return
    try:
        import termios
        import tty
    except ImportError:
        yield
        return
    loop = asyncio.get_running_loop()
    saved = termios.tcgetattr(fd)

    def on_key() -> None:
        try:
            data = os.read(fd, 1)
        except OSError:
            return
        if data in (b" ", b"t", b"\n", b"\r"):
            toggler()

    try:
        tty.setcbreak(fd)
        loop.add_reader(fd, on_key)
        print("[space 키: 생각 과정 펼치기/접기]", file=sys.stderr, flush=True)
        yield
    finally:
        with contextlib.suppress(Exception):
            loop.remove_reader(fd)
        with contextlib.suppress(Exception):
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _dump(obj) -> int:
    print(json.dumps(obj, indent=2, ensure_ascii=False))
    return 0


async def _run_agent(agent: SystemAgent, coro_factory, *, header: str) -> int:
    log = FileProgress(agent.progress, Path.cwd() / "research.log")
    agent.progress = log
    log.log(header)
    try:
        async with key_toggle(log):
            report = await coro_factory()
    except BaseException as exc:
        log.log(f"[예외] {type(exc).__name__}: {exc}")
        log.close(status="실패")
        raise
    log.log("--- 최종 결과 ---\n" + report)
    log.close()
    print(report)
    print(f"[research.log 기록 완료: {log.path}]", file=sys.stderr)
    return 0


def _resolved_source(agent: SystemAgent, explicit: str | None) -> str:
    if explicit:
        return explicit
    from core.provisioning import load_target_manifest
    manifest = load_target_manifest(agent.policy)
    if manifest and manifest.get("source_tree"):
        return manifest["source_tree"]
    raise ValueError("No --source given and no target source tree recorded; run 'setup target select' or pass --source")


async def _execute(args, root: Path) -> int:
    if args.command == "mode":
        if args.action == "show":
            print(Policy.load(root).mode)
        else:
            (root / ".system-agent-mode").write_text(args.value + "\n")
            print(args.value)
        return 0

    policy = Policy.load(root)
    agent = SystemAgent(policy, progress=ConsoleProgress())

    if args.command == "doctor":
        from core.provisioning import inspect as inspect_env
        report = inspect_env(policy)
        report["mode"] = policy.mode
        report["phase"] = agent.state.load().phase
        report["openai_model_configured"] = bool(policy.openai_model)
        report["openai_key_present"] = bool(os.environ.get("OPENAI_API_KEY"))
        report["network_allowlist"] = list(policy.allowed_domains)
        return _dump(report)

    if args.command == "status":
        from core.provisioning import offline_readiness
        state = agent.state.load()
        readiness = offline_readiness(policy)
        return _dump({
            "mode": policy.mode, "phase": state.phase, "phase_updated_at": state.updated_at,
            "ready_for_offline": readiness["ready"], "blockers": readiness["blockers"],
            "advisories": readiness["advisories"], "kernel_trees": readiness["kernel_trees"],
            "target_recorded": readiness["target_manifest"] is not None,
            "recent_phase_history": state.history[-5:],
        })

    if args.command == "models":
        return await _models(args, agent)
    if args.command == "setup":
        return await _setup(args, agent, root)
    if args.command == "research":
        return await _research(args, agent)
    if args.command == "crash":
        return await _crash(args, agent)
    if args.command == "findings":
        return _findings(args, agent)
    if args.command == "audit":
        return _audit(args, agent)

    if args.command == "programs":
        if args.action == "list":
            return _dump([{"key": pr.key, "name": pr.name, "domain": pr.domain, "bug_classes": sorted(pr.bug_classes), "severity_tiers": list(pr.severity_tiers)} for pr in agent.programs.list()])
        program = agent.programs.get(args.program)
        return _dump({"key": program.key, "name": program.name, "domain": program.domain, "summary": program.summary, "links": program.links, "scope": list(program.scope), "out_of_scope": list(program.out_of_scope), "severity_tiers": list(program.severity_tiers), "bug_classes": {n: {"tier": bc.tier, "note": bc.note} for n, bc in program.bug_classes.items()}, "report_fields": list(program.report_fields), "checklist": list(program.checklist), "instances": program.instances, "reference_domains": list(agent.programs.reference_domains)})

    if args.command == "report":
        return _report(args, agent)
    if args.command == "env":
        return _env(args, agent, policy)
    if args.command == "cloud":
        return await _cloud(args, agent, policy)
    if args.command == "skills":
        return await _skills(args, agent)

    # Direct tool shortcuts.
    if args.command == "read":
        arguments = {"path": args.path}
        if args.start_line:
            arguments["start_line"] = args.start_line
        if args.end_line:
            arguments["end_line"] = args.end_line
        result = await agent.skill("read_file", arguments)
    elif args.command == "ls":
        result = await agent.skill("list_dir", {"path": args.path, "recursive": args.recursive})
    elif args.command == "search":
        result = await agent.skill("grep", {"root": args.path, "pattern": args.pattern, "regex": args.regex})
    elif args.command == "fetch":
        result = await agent.skill("fetch", {"url": args.url})
    elif args.command == "web-search":
        result = await agent.skill("web_search", {"query": args.query})
    else:
        return 2
    print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
    return 0 if result.ok else 1


async def _models(args, agent: SystemAgent) -> int:
    policy = agent.policy
    if args.action == "list":
        import yaml
        roster = {}
        models_path = policy.workspace_roots[0] / "configs" / "models.yaml"
        if models_path.exists():
            roster = yaml.safe_load(models_path.read_text()) or {}
        from core.provisioning import ollama_status
        oll = ollama_status(policy)
        return _dump({"configured": roster, "active_mode": policy.mode, "ollama": {"reachable": oll["reachable"], "installed_models": oll["models"], "default_model": policy.ollama_model, "code_model": policy.ollama_code_model}, "openai": {"model": policy.openai_model or None, "key_present": bool(os.environ.get("OPENAI_API_KEY"))}})
    # test
    if args.provider == "ollama":
        from llm.ollama_provider import OllamaProvider
        try:
            provider = OllamaProvider(policy.ollama_model, policy.ollama_url, timeout=30, num_ctx=policy.ollama_num_ctx, num_gpu=policy.ollama_num_gpu)
            resp = await provider.complete([{"role": "user", "content": "Reply with the single word: ready"}], [])
            return _dump({"provider": "ollama", "model": policy.ollama_model, "ok": True, "reply": resp.text.strip()[:200]})
        except Exception as exc:
            return _dump({"provider": "ollama", "model": policy.ollama_model, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    # openai
    if not policy.openai_model:
        return _dump({"provider": "openai", "ok": False, "error": "openai_model is not configured in the active mode config"})
    if not os.environ.get("OPENAI_API_KEY"):
        return _dump({"provider": "openai", "ok": False, "error": "OPENAI_API_KEY is not set"})
    from llm.openai_provider import OpenAIProvider
    try:
        provider = OpenAIProvider(policy.openai_model, timeout=policy.request_timeout_seconds)
        resp = await provider.complete([{"role": "user", "content": "Reply with the single word: ready"}], [])
        return _dump({"provider": "openai", "model": policy.openai_model, "ok": True, "reply": resp.text.strip()[:200]})
    except Exception as exc:
        return _dump({"provider": "openai", "model": policy.openai_model, "ok": False, "error": f"{type(exc).__name__}: {exc}"})


async def _setup(args, agent: SystemAgent, root: Path) -> int:
    policy = agent.policy
    from core.provisioning import inspect as inspect_env, offline_readiness, kernel_trees
    if args.action == "docs":
        if policy.mode not in ("online", "hybrid"):
            raise ValueError("setup docs uses the Online provider; set mode to online (or hybrid) first: system-agent mode set online")
        agent.state.advance("ONLINE_DOCUMENTATION", note="setup docs")
        task = "Retrieve and summarize the current official kernelCTF rules, FAQ, server/setup docs, and published target instances, with source URLs and retrieval notes. Mark anything unavailable."
        return await _run_agent(agent, lambda: agent.online_docs.run(task, allow_network=True), header=f"setup docs (mode={policy.mode})")
    if args.action == "known-issues":
        if policy.mode not in ("online", "hybrid"):
            raise ValueError("setup known-issues uses the Online provider; set mode to online (or hybrid) first: system-agent mode set online")
        with contextlib.suppress(Exception):
            agent.state.advance("ONLINE_DOCUMENTATION", note="setup known-issues")
        task = (
            "Using official sources only, list kernelCTF bugs that are already KNOWN or FIXED and so would be "
            "duplicates/1-days: recently accepted kernelCTF submissions (if published) and upstream Linux fix "
            "commits relevant to the selected target. For each, give the fault area/symbol, the upstream fix "
            "commit hash if known, and the CVE if any, each with its source URL. Then show the exact "
            "'system-agent crash known add' commands the researcher can run to record them for the offline "
            "novelty check. Do not invent commits, CVEs, or URLs; mark anything you cannot confirm."
        )
        return await _run_agent(agent, lambda: agent.online_docs.run(task, allow_network=True), header=f"setup known-issues (mode={policy.mode})")
    if args.action == "target":
        program = agent.programs.get(getattr(args, "program", "kctf"))
        if args.target_action == "list":
            return _dump({"program": program.key, "instances": program.instances, "artifacts": program.artifacts, "note": "Confirm the CURRENT instances against the official docs (setup docs); do not assume these are up to date."})
        from core.setup import record_target
        path, manifest = record_target(policy, program, args.instance, source=args.source)
        with contextlib.suppress(Exception):
            agent.state.advance("ONLINE_PROVISIONING", note=f"target {args.instance} selected")
        print(f"[target manifest recorded: {path}]", file=sys.stderr)
        return _dump(manifest)
    if args.action == "dependencies":
        with contextlib.suppress(Exception):
            agent.state.advance("ONLINE_PROVISIONING", note="dependencies")
        return _dump({"environment": inspect_env(policy), "note": "Install missing build tools with your package manager; this platform proposes but does not run privileged installs."})
    if args.action == "kernel":
        trees = kernel_trees(policy)
        info = []
        for tree in trees:
            res = await agent.skill("kernel_build_info", {"kernel": tree})
            if res.ok:
                info.append({"tree": tree, "version": res.output.get("version"), "config_sha256": res.output.get("config_sha256"), "metadata": res.output.get("metadata")})
        return _dump({"kernel_trees": trees, "build_info": info, "note": "Add authorized checkouts to workspace_roots in configs/offline.yaml."})
    if args.action == "qemu":
        res = await agent.skill("kernel_vm_status", {})
        return _dump(res.output if res.ok else {"error": res.error})
    if args.action == "verify":
        with contextlib.suppress(Exception):
            agent.state.advance("ENVIRONMENT_VERIFICATION", note="setup verify")
        readiness = offline_readiness(policy)
        if readiness["ready"]:
            with contextlib.suppress(Exception):
                agent.state.advance("READY_FOR_OFFLINE", note="verification passed")
        readiness["phase"] = agent.state.load().phase
        return _dump(readiness)
    return 2


async def _research(args, agent: SystemAgent) -> int:
    policy = agent.policy
    from core.provisioning import offline_readiness
    if args.action == "prepare":
        return _dump(offline_readiness(policy))
    if args.action == "start":
        if policy.mode not in RESEARCH_MODES:
            raise ValueError(f"Offline research requires the local provider (mode offline or hybrid); current mode is {policy.mode}. Run: system-agent mode set offline")
        readiness = offline_readiness(policy)
        if not readiness["ready"]:
            print("system-agent: cannot start offline research — unmet prerequisites:", file=sys.stderr)
            for blocker in readiness["blockers"]:
                print(f"  - {blocker}", file=sys.stderr)
            return 1
        state = agent.state.advance("OFFLINE_RESEARCH", note="research start --offline")
        return _dump({"phase": state.phase, "ready": True, "advisories": readiness["advisories"], "message": "Offline research phase entered. Network skills are disabled for research. Re-entering online setup requires an explicit mode/setup command."})
    # source / memory / concurrency / patches
    if policy.mode not in RESEARCH_MODES:
        raise ValueError(f"Offline research requires the local provider (mode offline or hybrid); current mode is {policy.mode}")
    phase = agent.state.load().phase
    if phase not in ("OFFLINE_RESEARCH", "LOCAL_REPORTING"):
        raise ValueError(f"Not in the offline research phase (current: {phase}). Run: system-agent research start --offline")
    source = _resolved_source(agent, args.source)
    subsystem = args.subsystem or "."
    agent_map = {"source": agent.kernel_source, "memory": agent.kernel_memory, "concurrency": agent.kernel_concurrency, "patches": agent.kernel_patch}
    specialist = agent_map[args.action]
    task = args.task if subsystem == "." else f"Subsystem: {subsystem}. {args.task}"
    header = f"research {args.action} subsystem={subsystem} source={source}\ntask={task}"
    return await _run_agent(agent, lambda: specialist.inspect_and_run(source, task), header=header)


async def _crash(args, agent: SystemAgent) -> int:
    from core.known_issues import KnownIssuesStore
    if args.action == "list":
        store = agent.findings
        crashes = []
        if store.crashes_dir.is_dir():
            for entry in sorted(store.crashes_dir.glob("*.log")):
                crashes.append({"sha256": entry.stem, "path": str(entry), "bytes": entry.stat().st_size})
        return _dump({"crashes": crashes, "count": len(crashes)})
    if args.action == "known":
        store = KnownIssuesStore(agent.policy.workspace_roots[0])
        if args.known_action == "list":
            return _dump({"known_issues": store.list()})
        entry = {k: getattr(args, k) for k in ("signature", "fault_site", "fix_commit", "cve", "status", "note", "source") if getattr(args, k, None)}
        return _dump(store.add(entry))
    if args.action == "triage":
        from core.triage_flow import run_triage
        source = None
        with contextlib.suppress(Exception):
            source = _resolved_source(agent, args.source)
        raw = Path(args.input).read_text(errors="replace")
        result = await run_triage(agent, raw, source=source)
        return _dump(result)
    # analyze
    raw = Path(args.input).read_text(errors="replace")
    stored = agent.findings.store_crash_evidence(raw)
    from adapters import kasan, kcsan
    report = kcsan.parse_report(raw) if "KCSAN" in raw else kasan.parse_report(raw)
    return _dump({"evidence": stored, "parsed": report, "note": "Original crash evidence is stored immutably (mode 0444). Parsing treats the log as untrusted data."})


def _findings(args, agent: SystemAgent) -> int:
    store = agent.findings
    if args.action == "list":
        items = store.list()
        return _dump({"count": len(items), "findings": [{"finding_id": f["finding_id"], "status": f["status"], "bug_class": f["bug_class"], "subsystem": f.get("subsystem"), "confidence": f.get("confidence")} for f in items]})
    finding = store.get(args.finding_id)
    if finding is None:
        print(f"system-agent: no such finding: {args.finding_id}", file=sys.stderr)
        return 1
    return _dump(finding)


def _audit(args, agent: SystemAgent) -> int:
    path = agent.audit.path
    if not path.exists():
        return _dump({"events": [], "note": "No audit log yet"})
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if args.task and event.get("task_id") != args.task:
            continue
        events.append(event)
    return _dump({"events": events[-args.limit:], "shown": min(len(events), args.limit), "total_matched": len(events)})


def _report(args, agent: SystemAgent) -> int:
    from core.report_templates import blank_template, render
    if args.action == "generate":
        program = agent.programs.get(args.program)
        items = agent.findings.list()
        if args.finding:
            items = [f for f in items if f["finding_id"] == args.finding]
            if not items:
                print(f"system-agent: no such finding: {args.finding}", file=sys.stderr)
                return 1
        lines = [f"# {program.name} — findings report", "", f"_Program: {program.key} · {len(items)} finding(s)_", ""]
        for f in items:
            lines += [f"## {f['finding_id']} — {f['bug_class']} ({f['status']}, confidence {f.get('confidence')})",
                      f"- Subsystem: {f.get('subsystem')}", f"- Source: {f.get('source_file')} {f.get('line_range','')}".rstrip(),
                      f"- Function: {f.get('function')}", f"- Kernel commit: {f.get('kernel_commit')}",
                      f"- Validation: {f.get('validation',{}).get('status')} (reproducible={f.get('validation',{}).get('reproducible')})",
                      "", f.get("reasoning", ""), ""]
            if f.get("evidence"):
                lines.append("Evidence:")
                lines += [f"- {e}" for e in f["evidence"]]
                lines.append("")
        lines.append("> Findings are hypotheses unless validation.status=reproduced. No exploit code is included.")
        print("\n".join(lines) + "\n")
        return 0
    program = agent.programs.get(args.program)
    if args.action == "template":
        print(blank_template(program))
        return 0
    fields: dict = {}
    if args.fields_file:
        fields.update(json.loads(Path(args.fields_file).read_text()))
    if args.fields:
        fields.update(json.loads(args.fields))
    print(render(program, fields))
    return 0


def _env(args, agent: SystemAgent, policy: Policy) -> int:
    from core.kctf_env import scaffold, EXECUTABLE
    from security.filesystem import atomic_write, checked_path, open_dir
    program = agent.programs.get(args.program)
    if not program.instances:
        raise ValueError(f"Program '{program.key}' has no environment instances configured")
    if args.action == "instances":
        return _dump({"program": program.key, "instances": program.instances, "artifacts": program.artifacts})
    if args.instance not in program.instances:
        raise ValueError(f"Unknown instance '{args.instance}'. Configured instances: {', '.join(program.instances)}")
    source_fd, source_root, source_parts, _ = open_dir(policy, args.source)
    with contextlib.suppress(OSError):
        os.close(source_fd)
    source_abs = str(source_root.joinpath(*source_parts))
    dest_rel = (args.dest or f"envs/{program.key}-{args.instance}").rstrip("/")
    files = scaffold(program, args.instance, source=source_abs, dest_rel=dest_rel)
    dest_root, dest_parts, _ = checked_path(policy, dest_rel)
    dest_base = dest_root.joinpath(*dest_parts)
    if dest_base.exists() and not args.force:
        raise ValueError(f"Destination '{dest_base}' already exists; pass --force to overwrite")
    written = []
    for rel, content in files.items():
        target = f"{dest_rel}/{rel}"
        file_root, file_parts, _ = checked_path(policy, target)
        os.makedirs(file_root.joinpath(*file_parts[:-1]), exist_ok=True)
        atomic_write(policy, target, content.encode(), overwrite=args.force)
        if rel in EXECUTABLE:
            os.chmod(file_root.joinpath(*file_parts), 0o755)
        written.append(rel)
    print(f"[환경 생성 완료: {dest_base} — FETCH.md로 공식 아티팩트를 받고 run-qemu.sh를 검토하세요]", file=sys.stderr)
    return _dump({"created": str(dest_base), "instance": args.instance, "source": source_abs, "files": written})


async def _cloud(args, agent: SystemAgent, policy: Policy) -> int:
    if policy.mode != "hybrid":
        raise ValueError("cloud command requires Hybrid mode")
    payload = agent.router.cloud_payload_bytes(args.task)
    fingerprint = hashlib.sha256(payload).hexdigest()
    if args.action == "approval-hash":
        return _dump({"sha256": fingerprint, "outbound_request": json.loads(payload)})
    if args.approve_sha256 != fingerprint:
        raise ValueError("Exact cloud payload approval hash required")
    agent.approvals.grant("cloud_payload", payload)
    response = await agent.router.approved_cloud_task(args.task)
    print(response.text)
    return 0


async def _skills(args, agent: SystemAgent) -> int:
    if args.action == "list":
        return _dump([{"name": s.name, "category": s.category, "available": agent.permissions.available(s), "mutating": s.mutating, "cli_only": s.cli_only, "approval_required": s.requires_approval} for s in agent.registry.list()])
    if args.action == "info":
        skill = agent.registry.get(args.name)
        return _dump({"name": skill.name, "description": skill.description, "schema": skill.schema(), "output_schema": skill.output_schema(), "category": skill.category, "mutating": skill.mutating, "cli_only": skill.cli_only, "approval_required": skill.requires_approval})
    arguments = json.loads(args.arguments)
    skill = agent.registry.get(args.name)
    if not agent.permissions.available(skill):
        raise ValueError("Skill unavailable under current policy")
    payload = skill.approval_payload(arguments, agent.executor().context)
    fingerprint = hashlib.sha256(payload).hexdigest()
    if args.action == "approval-hash":
        return _dump({"skill": args.name, "sha256": fingerprint, "preview": skill.preview(arguments, agent.executor().context)})
    if args.approve_sha256:
        if args.approve_sha256 != fingerprint:
            raise ValueError("Approval hash does not match the exact current payload")
        agent.approvals.grant(args.name, payload)
    result = await agent.skill(args.name, arguments)
    print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
    return 0 if result.ok else 1


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        return asyncio.run(_execute(args, Path.cwd().resolve()))
    except (ValueError, KeyError, RuntimeError, OSError, SkillError) as exc:
        print(f"system-agent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
