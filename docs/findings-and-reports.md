# Findings and Reports

## The evidence-first schema

A candidate finding (`core/findings.py`) is always a **hypothesis** until it is
validated by reproduction. Findings are appended to `evidence/findings.jsonl`.

```json
{
  "finding_id": "KERNEL-LOCAL-0001",
  "status": "hypothesis",
  "bug_class": "kasan-use-after-free",
  "subsystem": "net/tls",
  "source_file": "net/tls/tls_sw.c",
  "function": "tls_push_record",
  "line_range": "",
  "kernel_commit": "",
  "target_config": "",
  "reasoning": "...",
  "evidence": ["crash:<sha>", "signature:crash:3bb7d2a5"],
  "contradictory_evidence": [],
  "validation": { "status": "not_tested", "reproducible": null, "detail": "" },
  "confidence": "low",
  "fix_references": []
}
```

{% hint style="warning" %}
The store **refuses** to mark a finding `validated` unless its validation record
is `status: "reproduced"` with `reproducible: true`. The model is never rewarded
for speculative findings — correctness, reproducibility, and source-backed
evidence come before the number of findings.
{% endhint %}

| `status` | `validation.status` | `confidence` |
| --- | --- | --- |
| `hypothesis`, `under_review`, `validated`, `rejected` | `not_tested`, `attempted`, `reproduced`, `not_reproduced` | `low`, `medium`, `high` |

## Browsing findings

```bash
system-agent findings list
system-agent findings show KERNEL-LOCAL-0001
```

## Reports

```bash
system-agent report generate --program kctf          # consolidate recorded findings
system-agent report generate --program kctf --finding KERNEL-LOCAL-0001
system-agent report template kctf                    # blank submission skeleton
system-agent report build kctf --fields-file notes/fields.json
```

`report generate` renders the recorded findings (hypotheses and validated) into
Markdown, preserving source evidence and distinguishing observation from
inference. A `bug_class` is annotated with the program's severity tier from
`configs/programs.yaml`. No exploit code is included in any report.
