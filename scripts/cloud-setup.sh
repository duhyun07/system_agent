#!/usr/bin/env bash
# Bootstrap the System Agent kernelCTF research platform on a cloud VM
# (tested on Ubuntu 24.04, e.g. a GCP n2-standard-4). Idempotent: safe to re-run.
#
# It installs the toolchain, Ollama + the default local model, creates a Python
# venv, installs the project, and runs `doctor`. It does NOT clone a Linux kernel
# source tree (that is large and optional) — see the note at the end.
#
# Usage (from the repo root on the VM):
#   bash scripts/cloud-setup.sh                 # full setup
#   SKIP_MODEL=1 bash scripts/cloud-setup.sh    # skip the (large) model pull
#   SKIP_OLLAMA=1 bash scripts/cloud-setup.sh   # skip Ollama entirely
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
MODEL="${MODEL:-qwen3:4b}"

log() { printf '\n\033[1;34m[cloud-setup]\033[0m %s\n' "$*"; }

log "Repo root: $REPO_ROOT"

# --- 1. System packages ----------------------------------------------------
log "Installing system packages (sudo apt-get)…"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq \
  python3-venv python3-pip \
  build-essential flex bison bc libelf-dev libssl-dev dwarves \
  gdb qemu-system-x86 git curl ca-certificates >/dev/null
log "System packages installed."

# --- 2. Ollama + local model ----------------------------------------------
if [ "${SKIP_OLLAMA:-0}" != "1" ]; then
  if ! command -v ollama >/dev/null 2>&1; then
    log "Installing Ollama (official installer)…"
    curl -fsSL https://ollama.com/install.sh | sh
  else
    log "Ollama already installed."
  fi
  # Ensure the server is running (systemd service on most installs; fallback to nohup).
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^ollama'; then
    sudo systemctl enable --now ollama || true
  elif ! curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    log "Starting ollama serve in the background…"
    nohup ollama serve >"$HOME/.ollama-serve.log" 2>&1 &
    sleep 3
  fi
  # Wait for the API to answer.
  for _ in $(seq 1 20); do
    curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
    sleep 1
  done
  if [ "${SKIP_MODEL:-0}" != "1" ]; then
    log "Pulling local model: $MODEL (this can take a few minutes)…"
    ollama pull "$MODEL"
  else
    log "SKIP_MODEL=1 — not pulling $MODEL."
  fi
else
  log "SKIP_OLLAMA=1 — skipping Ollama."
fi

# --- 3. Python environment + project --------------------------------------
if [ ! -d .venv ]; then
  log "Creating Python venv (.venv)…"
  python3 -m venv .venv
fi
log "Installing the project (editable, with test extras)…"
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -e '.[test]'

# --- 4. Cloud-friendly offline config note --------------------------------
# This VM has no GPU and (usually) no KVM. The platform reports that via
# `system-agent doctor` / `kernel_vm_status`; Ollama runs the model on CPU.
# `llm.num_gpu` in configs/offline.yaml is harmless with no GPU (Ollama falls
# back to CPU), so the committed config is left unchanged.

# --- 5. Verify -------------------------------------------------------------
log "Running: system-agent doctor"
./.venv/bin/system-agent doctor || true

log "Running the test suite (plugin autoload disabled)…"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ./.venv/bin/python -m pytest -q || true

cat <<'NOTE'

------------------------------------------------------------------------------
System Agent is set up on this VM. Next steps:

  source .venv/bin/activate
  system-agent doctor
  system-agent status

To do offline source research you need an authorized Linux checkout. Add one and
point configs/offline.yaml:workspace_roots at it, for example:

  git clone --depth 1 -b linux-6.12.y \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git ~/linux-6.12

This VM has no GPU and no KVM: the local model runs on CPU (slower), and dynamic
VM tests require a host/instance with /dev/kvm. Everything else works.
------------------------------------------------------------------------------
NOTE
log "Done."
