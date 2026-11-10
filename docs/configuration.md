# Configuration

Config files live in `configs/`. The active mode config is chosen by
`.system-agent-mode`.

| File | Purpose |
| --- | --- |
| `offline.yaml` | Ollama model/GPU/context, workspace roots, research network allowlist, limits |
| `online.yaml` | OpenAI model, prices, budget |
| `hybrid.yaml` | hybrid settings |
| `models.yaml` | model roster (offline/online) |
| `resources.yaml` | resource budget (one inference, one build/test at a time) |
| `skills.yaml` | per-skill permission rules (filesystem / kernel / network) |
| `programs.yaml` | kernelCTF program profile (scope, bug-class → tier, report fields, checklist, target instances) |

## Workspace roots

Each mode config may set `workspace_roots` to absolute paths or paths relative to
the project. Add an authorized Linux checkout there before analyzing it; the CLI
rejects unconfigured roots. A tree counts as a kernel tree when it has
`Makefile`, `Kconfig`, and `include/linux/`.

## Offline model + GPU (excerpt)

```yaml
# configs/offline.yaml
llm:
  ollama_url: http://127.0.0.1:11434
  ollama_model: qwen3:4b
  code_model: qwen2.5-coder:7b
  num_ctx: 8192
  num_gpu: 999        # offload all layers that fit in VRAM; 0 = CPU-only
```

## Skill permissions (excerpt)

```yaml
# configs/skills.yaml
skills:
  kernel:
    kernel_source_search: allow
    kernel_commit_diff: allow
    kernel_test_run: approval_required   # also CLI-only in code
  network:
    fetch:
      offline: allowlisted
      hybrid: allowlisted_and_payload_approval
```

## State files

| File | Meaning |
| --- | --- |
| `.system-agent-mode` | the active mode |
| `.system-agent-phase` | the persisted workflow phase + history |
| `research/kernel/target-manifest.json` | the selected target |
| `research/kernel/crash-index.jsonl` | crash signatures seen locally |
| `research/kernel/known-issues.json` | known/fixed bugs for novelty checks |
| `evidence/findings.jsonl` | recorded findings |
| `evidence/crashes/<sha>.log` | immutable original crash evidence |
| `logs/audit.jsonl` | skill audit log (hashes only) |
