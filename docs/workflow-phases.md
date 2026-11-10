# Workflow Phases

A persisted state machine (`core/state_machine.py`, stored in
`.system-agent-phase`) enforces the Online-setup → Offline-research progression:

```
UNINITIALIZED
   → ONLINE_DOCUMENTATION
   → ONLINE_PROVISIONING
   → ENVIRONMENT_VERIFICATION
   → READY_FOR_OFFLINE
   → OFFLINE_RESEARCH
   → LOCAL_REPORTING
```

| Phase | Provider | Set by |
| --- | --- | --- |
| `ONLINE_DOCUMENTATION` | OpenAI | `setup docs`, `setup known-issues` |
| `ONLINE_PROVISIONING` | OpenAI | `setup target select`, `setup dependencies` |
| `ENVIRONMENT_VERIFICATION` | OpenAI | `setup verify` |
| `READY_FOR_OFFLINE` | — | `setup verify` (when ready) |
| `OFFLINE_RESEARCH` | Ollama | `research start --offline` |
| `LOCAL_REPORTING` | Ollama | reporting |

{% hint style="danger" %}
**The one-way rule.** Once in `OFFLINE_RESEARCH` (or later), the machine never
transitions back to an online phase automatically — a failure is *never* treated
as a reason to go back online. Re-entering setup is an explicit user action
(`StateMachine.reset_online`). Forward jumps across several phases are allowed;
backward transitions to an online phase are rejected.
{% endhint %}

## Offline network isolation

Offline research additionally runs with **all network skills removed** from the
offered tool set, independent of the mode allowlist. A research task cannot reach
the network even if the active mode's `allowed_domains` is non-empty.

## The readiness gate

`research start --offline` (and `setup verify`) call
`core.provisioning.offline_readiness`, which refuses to enter offline research
unless every blocking prerequisite is met and explains how to resolve each one:

| Check | Blocking | Fix |
| --- | --- | --- |
| local kernel source present | yes | add an authorized checkout to `workspace_roots` |
| target configuration recorded | yes | `setup target select` |
| Ollama reachable | yes | `ollama serve` |
| local model present | yes (if reachable) | `ollama pull qwen3:4b` |
| analysis tools (git, gdb) | advisory | install them |
| memory / disk | advisory | free resources |

```bash
system-agent status          # phase + readiness summary
system-agent research prepare  # full readiness report
```
