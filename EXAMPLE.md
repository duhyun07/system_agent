# Walkthrough — kernelCTF research with System Agent

This is the intended Online-setup → Offline-research flow. Commands print JSON to
stdout and human-readable progress to stderr, so you can redirect results while
still watching progress.

> Reminder: the deliverable is evidence-backed triage and reporting, not exploit
> code. A candidate finding is a hypothesis until it is reproduced in an isolated
> VM. Dynamic tests are approval-gated and VM-isolated.

## 0. Health and phase

```bash
system-agent doctor     # python deps, toolchain, QEMU/KVM, Ollama, workspace roots
system-agent status     # workflow phase + offline-readiness summary
```

`doctor` on this host reports, for example, Ollama reachable with `qwen3:4b`
present, QEMU available, and (if exposed) KVM accelerated. `status` starts at
phase `UNINITIALIZED`.

## 1. Online setup (Phase A — OpenAI)

Documentation retrieval uses the Online provider:

```bash
system-agent mode set online
system-agent setup docs            # fetch + summarize official kernelCTF docs
system-agent setup known-issues    # surface known/fixed bugs + patch info (optional)
```

`setup docs` only reads official sources (google.github.io kernelCTF pages and
the google/security-research kernelctf directory) and reports target instances,
versions, and artifacts with source URLs. It never invents versions or URLs, and
it does not do vulnerability discovery.

Record which target you are analyzing (deterministic, no network needed):

```bash
system-agent setup target list
system-agent setup target select --instance lts --source /home/pwner7/linux-6.12
```

This writes `research/kernel/target-manifest.json` with the instance, the local
source tree, and placeholders for the exact version/commit to confirm from the
official `metadata.json`.

## 2. Provisioning and verification

```bash
system-agent setup dependencies    # toolchain / QEMU / Ollama inspection
system-agent setup kernel          # authorized kernel trees + build provenance
system-agent setup qemu            # QEMU/KVM status for isolated VMs
system-agent setup verify          # readiness gate
```

`setup verify` advances to `READY_FOR_OFFLINE` when all blocking prerequisites
are met (a local kernel tree, a recorded target, Ollama reachable with the model
present) and otherwise lists each blocker with a fix.

## 3. Enter offline research (Phase B — Ollama)

```bash
system-agent mode set offline
system-agent research prepare          # show prerequisites
system-agent research start --offline  # gate + enter OFFLINE_RESEARCH
```

From here, **network skills are disabled** for research. The phase will not
return to an online phase automatically; re-entering setup is explicit.

## 4. Source, memory, concurrency, and patch analysis

```bash
system-agent research source --subsystem net/tls
system-agent research memory --subsystem mm/slub.c
system-agent research concurrency --subsystem fs
system-agent research patches --subsystem mm
```

Each runs the local model over the authorized tree with the kernel-research
skills (`kernel_source_search`, `kernel_function_lookup`,
`kernel_callgraph_lookup`, `kernel_config_lookup`, `kernel_commit_diff`, …) plus
the filesystem skills. The final answer is rejected unless it cites inspected
source lines in `path:line` form. Full progress and the model's reasoning stream
are written to `research.log`.

## 5. Crash triage and novelty

```bash
# Quick structured parse + immutable evidence storage:
system-agent crash analyze --input ./crash.log

# Full novelty workflow (dedup + patch correlation + verdict):
system-agent crash triage --input ./crash.log --source /home/pwner7/linux-6.12
system-agent crash list
system-agent crash known list
```

`crash triage` parses the (untrusted) log, stores the original immutably, then
judges whether the crash is already-known:

- It matches the crash signature against the local crash index (duplicate) and
  the known-issue registry, and correlates the fault symbol against the local
  kernel git history for an upstream fix (a 1-day indicator).
- **Known** → it recommends continuing the search for a different crash.
- **Novel** → it records a candidate finding (a hypothesis) and drafts a report
  under `reports/<finding_id>.md`.

Populate the known-issue registry from official info (`setup known-issues`
online) or by hand:

```bash
system-agent crash known add --signature crash:3bb7d2a5 --fix-commit <sha> --note "already submitted"
```

## 6. Findings and reports

```bash
system-agent findings list
system-agent findings show KERNEL-LOCAL-0001
system-agent report generate --program kctf
system-agent report template kctf
system-agent report build kctf --fields-file notes/fields.json
```

A finding is only ever `validated` with a `validation.status=reproduced` record;
the store refuses to mark an unreproduced finding as confirmed.

## 7. Local repro environment and dynamic testing

```bash
system-agent env init kctf --instance lts --source /home/pwner7/linux-6.12
```

Scaffolds a review-ready QEMU repro setup (boot script, gdb helper, config
notes, fetch checklist, manifest). You obtain the official artifacts, review the
scripts, and run the VM yourself. Dynamic testing goes through the CLI-only,
approval-gated `kernel_test_run`, which refuses to run without an explicit
VM-isolation confirmation and never runs model-generated code.

## 8. Audit

```bash
system-agent audit show --task <task_id>
```

Every skill call is logged (name, task/origin, argument and result hashes,
status, duration) — never the arguments or content themselves.
