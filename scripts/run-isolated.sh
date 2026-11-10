#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: scripts/run-isolated.sh read|ls|search ..." >&2
  exit 2
fi
case "$1" in
  read|ls|search|doctor) ;;
  skills)
    case "${2:-}" in
      list|info) ;;
      *) echo "isolated runner accepts only read-only skill commands" >&2; exit 2 ;;
    esac
    ;;
  *) echo "isolated runner accepts only read-only commands" >&2; exit 2 ;;
esac

project_root="$(cd "$(dirname "$0")/.." && pwd)"
exec docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 512m --cpus 1 \
  --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount "type=bind,src=$project_root/research,dst=/workspace/research,readonly" \
  --mount "type=bind,src=$project_root/logs,dst=/workspace/logs" \
  system-agent:local "$@"
