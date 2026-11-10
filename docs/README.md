# System Agent

System Agent is a local-first Linux kernel research platform dedicated to
Google's official **kernelCTF** program. It takes a researcher from
official-documentation setup (online) through offline, source-level kernel
analysis, crash triage, and reporting — with a strict separation between two AI
responsibilities.

| Responsibility | Provider | Phase |
| --- | --- | --- |
| Official-documentation research, environment provisioning, verification | **OpenAI GPT** (online) | A |
| Kernel source analysis, candidate discovery, crash triage, regression analysis, reporting | **Ollama** (offline) | B |

The main orchestrator class is `core.orchestrator.SystemAgent`; the CLI command
is `system-agent`.

{% hint style="warning" %}
**Scope.** The deliverable is evidence-backed root-cause analysis and triage —
**not** exploit code, privilege escalation, persistence, or mitigation bypass. A
candidate finding is a *hypothesis* until it is reproduced in an isolated VM, and
the platform never marks an unverified finding as a confirmed vulnerability.
Dynamic testing is approval-gated and restricted to isolated VMs.
{% endhint %}

## What's in this book

- [Getting Started](getting-started.md) — install and the first run-through.
- [Modes and Providers](modes-and-providers.md) — offline/online/hybrid, the
  local model, and GPU offload.
- [Workflow Phases](workflow-phases.md) — the persisted state machine and the
  one-way offline rule.
- [CLI Reference](cli-reference.md) — every command.
- [Skills](skills.md) — filesystem, network, and kernel-research skills.
- [Crash Triage and Novelty](crash-triage.md) — known-vs-novel judgment.
- [Findings and Reports](findings-and-reports.md) — the evidence-first schema.
- [Repro Environment and Dynamic Testing](repro-environment.md) — the isolated-VM
  workflow.
- [Configuration](configuration.md) — the config files.
- [Security Model](security.md) — how isolation and authorization are enforced.
- [Limitations](limitations.md) — what is partial or out of scope.

A Korean version is under [한국어 문서](ko/README.md).
