# Skills

Every skill is invoked through one executor (`skills/executor.py`) shared by the
CLI and the model. Each has JSON-Schema input validation, structured output, a
timeout, permission rules (`configs/skills.yaml`), workspace-path validation,
audit logging, and explicit error handling. There is **no unrestricted shell
skill**.

All external documentation, source files, and crash logs are treated as
**untrusted data**, never as instructions.

## Filesystem

| Skill | Purpose |
| --- | --- |
| `read_file` | bounded UTF-8 read of an authorized file |
| `write_file` | atomic create; overwrite needs approval |
| `edit_file` | exact text replace, hash-bound approval |
| `apply_patch` | multi-file exact patches, approval + expected hashes |
| `list_dir` | list entries, no symlink following |
| `search_files` | find files by basename glob |
| `grep` | bounded literal/regex content search |
| `file_info` | metadata + optional SHA-256 |

## Network

| Skill | Purpose |
| --- | --- |
| `fetch` | bounded HTTP(S) GET from an allowlisted domain, DNS-pinned |
| `web_search` | keyless DuckDuckGo (or Brave with a key); returns candidates |

Network skills are available only when the active mode has a domain allowlist,
and are **removed entirely** during offline research.

## Kernel research

| Skill | Purpose |
| --- | --- |
| `kernel_source_search` | content search scoped to a subsystem |
| `kernel_function_lookup` | locate a function's definition site(s) |
| `kernel_callgraph_lookup` | heuristic callers + callees of a function |
| `kernel_config_lookup` | CONFIG_* state in a `.config` |
| `kernel_commit_diff` | read-only git show/diff/log/head over a local tree |
| `kernel_log_parse` | parse KASAN/KCSAN/Oops into structure + signature |
| `kernel_crash_deduplicate` | group crash logs by normalized signature |
| `kernel_build_info` | Makefile version, kernel.release, config hash, metadata |
| `kernel_coverage_read` | read an existing KCOV/coverage summary |
| `kernel_vm_status` | QEMU/KVM availability + host resources |
| `kernel_test_run` | **CLI-only, approval-gated** dynamic test runner |

{% hint style="warning" %}
`kernel_test_run` is never offered to or callable by the model. It requires
one-use approval, refuses to run without an explicit VM-isolation confirmation,
runs only a researcher-provided executable harness inside the workspace (never
model-generated code or a shell string), and applies a wall-clock timeout plus
CPU/address-space rlimits.
{% endhint %}

## Permissions

`configs/skills.yaml` maps each skill to a rule (`allow`, `workspace_only`,
`approval_required`, or per-mode network rules). A model cannot change workspace
roots, allowlists, approval state, timeouts, or limits through skill arguments —
authorization is enforced in Python. See [Security Model](security.md).
