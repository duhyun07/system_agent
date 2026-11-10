# Security Model

System Agent is a kernelCTF research platform. Its deliverable is evidence-backed
root-cause analysis, triage, crash deduplication, and reporting. It does **not**
implement or automate privilege escalation, persistence, kernel-protection
bypass, or exploit-chain development, and it does not generate exploit code.
Research operates on authorized local kernel checkouts and, for dynamic tests, on
approved isolated VMs only.

## Untrusted data

Repository files, kernel source, crash logs, fetched pages, and search snippets
are untrusted evidence. The system prompt tells models to ignore embedded
instructions, but **authorization is enforced in Python**. Skills are exposed to
a model only when policy permits them, and a model cannot alter workspace roots,
allowlists, approval state, timeouts, or limits through skill arguments.

## Phase isolation

The state machine enforces the Online-setup → Offline-research progression. Once
in `OFFLINE_RESEARCH`, it never transitions back to an online phase
automatically; re-entering setup is an explicit user action. Offline research
also runs with all network skills removed from the offered tool set, independent
of the mode allowlist — a research task cannot reach the network.

## Filesystem

Access uses authorized roots, rejects traversal and protected paths, and opens
each directory component with `O_NOFOLLOW`. Reads and writes refuse symlinks.
Writes use a temp file in the target directory, `fsync`, and atomic replacement.
Exact edits and patches require approval and expected file hashes.

## Network

Disabled in offline mode. In online/hybrid, destinations require exact or
explicitly wildcarded domain allowlisting; IP literals, nonstandard ports, and
private/loopback/link-local/reserved/metadata addresses are rejected. DNS is
checked before each request and redirect and the connection is pinned to the
checked IP. HTTPX runs with proxies disabled and TLS verification on.

## Dynamic testing

`kernel_test_run` is CLI-only, approval-gated, refuses to run without explicit VM
isolation, runs only a researcher-provided harness (never model-generated code or
a shell string), and applies a timeout plus CPU/address-space rlimits with
bounded output. WSL alone is not a sandbox; the syzkaller adapter is read-only.

## Immutable evidence and findings

`store_crash_evidence` writes each raw log once under `evidence/crashes/<sha>.log`
with mode `0444` and `O_EXCL`, so a finding's cited evidence cannot be silently
altered. Findings default to `hypothesis`/`not_tested`; the store refuses to mark
a finding `validated` without a `reproduced` validation record.

## Audit

`logs/audit.jsonl` records skill name, task/origin, argument and result hashes,
status, and duration — never the arguments or content themselves, and no API key
values.

## Hybrid cloud approval

Hybrid cloud calls consume one-use approval bound to the SHA-256 of the exact
serialized task payload; hybrid network skill calls also consume one-use approval
for exact arguments. Do not treat a displayed SHA-256 alone as consent without
reviewing the corresponding payload and diff.
