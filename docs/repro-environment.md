# Repro Environment and Dynamic Testing

## Scaffolding a local repro VM

```bash
system-agent env instances kctf
system-agent env init kctf --instance lts --source /path/to/linux
```

This writes a review-ready local QEMU repro/debug setup (`core/kctf_env.py`):

| File | Purpose |
| --- | --- |
| `README.md` | the workflow for this instance |
| `FETCH.md` | how to obtain and verify the official artifacts (manual) |
| `run-qemu.sh` | boot a kernel YOU provide, under QEMU |
| `scripts/attach-gdb.sh` | attach gdb to the QEMU stub |
| `config/notes.md` | config options to confirm against the official `.config` |
| `notes/fields.json` | report fields to fill |
| `env.json` | machine-readable manifest |

{% hint style="info" %}
`env init` **downloads nothing, builds nothing, and runs nothing.** You obtain
the official release artifacts, verify their checksums, review the scripts, and
run the VM yourself under the kernelCTF rules.
{% endhint %}

## Dynamic testing

Dynamic tests run only through the `kernel_test_run` skill, which is:

- **CLI-only** — never offered to or callable by the model;
- **approval-gated** — one-use approval bound to the exact arguments;
- **isolation-required** — refuses to run unless the caller explicitly confirms
  VM isolation (`isolation_confirmed=true`);
- **harness-only** — runs a researcher-provided executable inside the workspace,
  never model-generated code and never a shell string;
- **bounded** — wall-clock timeout plus best-effort CPU/address-space rlimits and
  bounded captured output.

Without approval and isolation confirmation it executes nothing and only returns
a prerequisite report.

## QEMU / KVM status

```bash
system-agent setup qemu          # or: kernel_vm_status skill
```

Reports whether a QEMU system emulator and KVM acceleration are available.

{% hint style="warning" %}
WSL alone is **not** treated as a secure sandbox for untrusted kernel binaries.
In WSL2, KVM may or may not be exposed; the tool reports the real state and never
assumes acceleration. Host-kernel fuzzing is out of scope, and the syzkaller
adapter is read-only (it summarizes an existing authorized run and never launches
fuzzing). Risky dynamic experiments require a separate isolated VM.
{% endhint %}

For static scans of untrusted material, `scripts/run-isolated.sh` adds Docker OS
isolation (no network, read-only mounts, dropped capabilities, resource caps).
The image must be built separately; the isolated runner cannot use Ollama or
mutate files.
