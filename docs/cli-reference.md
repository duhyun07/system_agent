# CLI Reference

All commands print JSON to stdout and progress to stderr. `system-agent <cmd> -h`
shows per-command help.

## General

```bash
system-agent doctor            # environment + provider health
system-agent status            # phase + offline-readiness summary
system-agent mode show|set <offline|online|hybrid>
```

## Models

```bash
system-agent models list
system-agent models test --provider ollama
system-agent models test --provider openai
```

## Online setup (Phase A)

```bash
system-agent setup docs                 # fetch/summarize official kernelCTF docs (online)
system-agent setup known-issues         # surface known/fixed bugs + patch info (online)
system-agent setup target list
system-agent setup target select --instance <lts|cos|mitigation> --source <tree>
system-agent setup dependencies         # toolchain/QEMU/Ollama inspection
system-agent setup kernel               # kernel trees + build provenance
system-agent setup qemu                 # QEMU/KVM status
system-agent setup verify               # readiness gate → READY_FOR_OFFLINE
```

## Offline research (Phase B)

```bash
system-agent research prepare
system-agent research start --offline
system-agent research source      --subsystem <dir> [--source <tree>] [--task ...]
system-agent research memory      --subsystem <dir>
system-agent research concurrency --subsystem <dir>
system-agent research patches     --subsystem <dir>
```

Research commands require a research mode (`offline` or `hybrid`) and the
`OFFLINE_RESEARCH` phase. `--source` defaults to the recorded target's tree.

## Crash analysis

```bash
system-agent crash analyze --input ./crash.log        # parse + store immutably
system-agent crash triage  --input ./crash.log [--source <tree>]
system-agent crash list
system-agent crash known list
system-agent crash known add --signature <sig> --fix-commit <sha> --cve <id> --note <text>
```

## Findings and reports

```bash
system-agent findings list
system-agent findings show <FINDING_ID>
system-agent report generate --program kctf [--finding <ID>]
system-agent report template kctf
system-agent report build kctf --fields-file notes/fields.json
```

## Auditing

```bash
system-agent audit show [--task <task_id>] [--limit N]
```

## Local repro environment

```bash
system-agent env instances kctf
system-agent env init kctf --instance lts --source <tree> [--dest <dir>] [--force]
```

## Low-level skills and direct tools

```bash
system-agent skills list
system-agent skills info <name>
system-agent skills approval-hash <name> '<json-args>'
system-agent skills run <name> '<json-args>' [--approve-sha256 <hash>]
system-agent read <path> [--start-line N] [--end-line N]
system-agent ls <path> [--recursive]
system-agent search <pattern> [--path <dir>] [--regex]
system-agent fetch <url>            # allowlisted domains only
system-agent web-search <query>
system-agent cloud approval-hash|run <task> [--approve-sha256 <hash>]   # hybrid only
```
