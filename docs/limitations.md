# Limitations

Known gaps and environment-dependent behavior, reported honestly rather than
hidden:

- **syzkaller** — `syz-manager` is not required to be installed; the syzkaller
  adapter is read-only and summarizes an existing authorized run. This platform
  does not orchestrate fuzzing, and host-kernel fuzzing is out of scope.
- **Optional code model** — `qwen2.5-coder:7b` is not pulled by default. Enable
  it with `ollama pull qwen2.5-coder:7b`.
- **Call graph / function lookup** — heuristic (column-0 definition style and
  grep-based caller/callee detection), not a cscope/clang index. Confirm by
  reading the cited lines.
- **Online agents** — require `OPENAI_API_KEY`, a configured `openai_model`, and
  a positive budget. The default test suite uses mocked providers and needs no
  paid key.
- **KVM in WSL2** — not guaranteed. `kernel_vm_status` reports the real state; if
  KVM is unavailable, QEMU falls back to TCG software emulation (much slower),
  and a separate isolated VM is the documented alternative for risky experiments.
- **Cross-process edits** — can race between the final hash check and rename; use
  a dedicated workspace or external locking if multiple writers share a tree.
- **Spending estimates** — use configured token prices and a conservative token
  approximation; real provider bills may differ.
- **Abliteration / refusal removal** — intentionally **not** provided. The
  platform does not modify the local model's safety behavior.

## Testing note

The repository's own tests pass (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python
-m pytest -q`). Containerized isolation (`scripts/run-isolated.sh`) requires
Docker and is not exercised by the default unit tests.
