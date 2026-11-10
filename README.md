# System Agent

System Agent is a local-first research platform dedicated to Google's official
**kernelCTF** program. It helps a researcher move from official-documentation
setup to offline, source-level Linux kernel analysis and crash triage, with a
strict separation between two AI responsibilities:

- **Online (OpenAI GPT):** official-documentation research, environment
  provisioning guidance, and verification. Phase A only.
- **Offline (Ollama):** local kernel source analysis, candidate-vulnerability
  discovery, crash triage, regression analysis, and reporting. Phase B only.

The main orchestrator class is `core.orchestrator.SystemAgent`; the CLI command
is `system-agent`. The deliverable is evidence-backed root-cause analysis and
triage — **not** exploit code, privilege escalation, persistence, or mitigation
bypass. Dynamic testing is restricted to approved, isolated VMs.

> Scope: Linux kernel research within the documented scope of Google's kernelCTF
> program and locally authorized test environments only. A candidate finding is
> a hypothesis until it is reproduced; the tool never labels an unverified
> finding a confirmed vulnerability.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/system-agent doctor
```

Dependencies: `httpx`, the official `openai` SDK, `PyYAML`, `jsonschema`,
`regex`. API keys are read from the environment; `.env` is never auto-loaded.

## Modes and providers

- **offline** (default): local Ollama on loopback. Used for Phase B research.
- **online**: OpenAI Responses API. Used for Phase A documentation/setup. Needs
  `OPENAI_API_KEY`, an `openai_model`, per-million-token prices, and a positive
  `max_spend_usd` in `configs/online.yaml`.
- **hybrid**: Ollama for research; cloud inference only via an explicit,
  SHA-256-approved `cloud` command. No automatic cloud fallback.

```bash
system-agent mode show
system-agent mode set offline        # research
system-agent mode set online         # documentation/setup
```

### Local model and GPU

The offline provider talks to Ollama on `127.0.0.1:11434`. Defaults:
`qwen3:4b` (general) and `qwen2.5-coder:7b` (optional code analysis), 8192
context, one inference at a time. `configs/offline.yaml` sets `llm.num_gpu: 999`
to offload every model layer that fits onto the GPU (RTX 4060 8GB); Ollama
clamps to available VRAM. Set `num_gpu: 0` to force CPU-only. Confirm placement
with `ollama ps` (expect `100% GPU` for `qwen3:4b`).

## Workflow phases

A persisted state machine (`.system-agent-phase`) enforces the progression:

```
UNINITIALIZED → ONLINE_DOCUMENTATION → ONLINE_PROVISIONING
            → ENVIRONMENT_VERIFICATION → READY_FOR_OFFLINE
            → OFFLINE_RESEARCH → LOCAL_REPORTING
```

`OFFLINE_RESEARCH` never returns to an online phase automatically — a failure
is never treated as a reason to go back online. Re-entering setup is an explicit
user action. Offline research runs with **all network skills disabled**,
independent of the mode allowlist.

## First-use commands

```bash
# 1. Health + phase
system-agent doctor
system-agent status

# 2. Online setup (set mode online for 'setup docs')
system-agent setup docs                    # fetch/summarize official kernelCTF docs
system-agent setup target list             # show configured target instances
system-agent setup target select --instance lts --source /path/to/linux
system-agent setup dependencies            # inspect toolchain/QEMU/Ollama
system-agent setup kernel                  # kernel trees + build provenance
system-agent setup qemu                    # QEMU/KVM status for isolated VMs
system-agent setup verify                  # readiness gate → READY_FOR_OFFLINE

# 3. Enter offline research
system-agent research prepare              # show prerequisites
system-agent research start --offline      # gate + enter OFFLINE_RESEARCH

# 4. Offline kernel research (Ollama only, no network)
system-agent research source --subsystem mm
system-agent research memory --subsystem net/tls
system-agent research concurrency --subsystem fs
system-agent research patches --subsystem mm/slub.c

# 5. Crash analysis
system-agent crash analyze --input ./crash.log   # stores evidence immutably
system-agent crash list

# 6. Findings and reports
system-agent findings list
system-agent findings show KERNEL-LOCAL-0001
system-agent report generate --program kctf

# 7. Audit
system-agent audit show --task <task_id>
```

`models list` shows the configured roster and installed Ollama models;
`models test --provider ollama|openai` does a minimal connectivity round-trip.

## Skills

Filesystem (`read_file`, `write_file`, `edit_file`, `list_dir`, `search_files`,
`grep`, `file_info`, `apply_patch`), network (`fetch`, `web_search`), and
kernel-research skills:

`kernel_source_search`, `kernel_function_lookup`, `kernel_callgraph_lookup`,
`kernel_config_lookup`, `kernel_commit_diff`, `kernel_log_parse`,
`kernel_crash_deduplicate`, `kernel_build_info`, `kernel_coverage_read`,
`kernel_vm_status`, and the CLI-only, approval-gated `kernel_test_run`.

Every skill has JSON-Schema input validation, structured output, a timeout,
permission rules, workspace-path validation, audit logging, and explicit error
handling. There is no unrestricted shell skill. `kernel_test_run` is never
offered to the model, requires one-use approval, refuses to run without an
explicit VM-isolation confirmation, and never executes model-generated code.

All external documentation, source files, and crash logs are treated as
**untrusted data**, never as instructions.

See [EXAMPLE.md](EXAMPLE.md) for a step-by-step offline research walkthrough and
[SECURITY.md](SECURITY.md) for the security model.

## Local repro environment

`system-agent env init kctf --instance lts --source /path/to/linux` scaffolds a
review-ready local QEMU repro/debug setup (boot script, gdb helper, config
notes, fetch checklist, manifest). It downloads nothing, builds nothing, and
runs nothing; you obtain the official release artifacts, review the scripts, and
run the VM yourself under the kernelCTF rules.
