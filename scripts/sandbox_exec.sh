#!/usr/bin/env bash
# sandbox_exec.sh - run exploit/PoC code somewhere the blast radius is contained.
#
#   bash sandbox_exec.sh <script-file> [-- arg1 arg2 ...]
#
# Two tiers, in order of preference:
#
#   1. Docker, if installed - a throwaway container, no network by default,
#      memory/CPU capped, filesystem discarded on exit (--rm). This is the
#      real isolation: a PoC that goes wrong (fork bomb, unexpected write,
#      runaway loop) dies with the container.
#
#   2. Fallback - a resource-limited subprocess (ulimit + timeout) in the
#      current OS. This is NOT isolation. It bounds runaway resource use and
#      kills long-running processes, but the code still runs with the
#      current user's filesystem and network access. Say so loudly - a tool
#      that quietly claims "sandboxed" when it means "rate-limited" is worse
#      than one that's honest about running unsandboxed.
#
# Exit code and stdout/stderr from the script are passed through.

set -uo pipefail

SCRIPT="${1:-}"
shift || true
[ "${1:-}" = "--" ] && shift || true

if [ -z "$SCRIPT" ] || [ ! -f "$SCRIPT" ]; then
  echo "usage: sandbox_exec.sh <script-file> [-- args...]" >&2
  exit 2
fi

TIMEOUT="${SANDBOX_TIMEOUT:-30}"
MEM_MB="${SANDBOX_MEM_MB:-256}"
NETWORK="${SANDBOX_NETWORK:-none}"   # none | bridge - only open network if the PoC needs it

ext="${SCRIPT##*.}"
case "$ext" in
  py)
    RUNNER=""
    for cand in python3 python py; do
      command -v "$cand" >/dev/null 2>&1 && "$cand" -c "" >/dev/null 2>&1 && { RUNNER="$cand"; break; }
    done
    [ -z "$RUNNER" ] && { echo "[sandbox] no working python interpreter on PATH" >&2; exit 127; }
    IMAGE="python:3.12-slim"
    ;;
  js)  RUNNER="node"    ; IMAGE="node:22-slim" ;;
  sh)  RUNNER="bash"    ; IMAGE="bash:5" ;;
  *)   RUNNER="cat"     ; IMAGE="alpine:3" ;;
esac

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "[sandbox] docker: --rm --network=$NETWORK --memory=${MEM_MB}m --cpus=0.5 --pids-limit=64" >&2
  exec docker run --rm \
    --network="$NETWORK" \
    --memory="${MEM_MB}m" \
    --cpus="0.5" \
    --pids-limit=64 \
    --read-only \
    --tmpfs /tmp:rw,size=32m \
    -v "$(cd "$(dirname "$SCRIPT")" && pwd)/$(basename "$SCRIPT")":"/poc.$ext":ro \
    "$IMAGE" "$RUNNER" "/poc.$ext" "$@"
fi

echo "[sandbox] docker not available - falling back to a resource-limited" >&2
echo "[sandbox] subprocess. THIS IS NOT ISOLATION: the PoC runs with this" >&2
echo "[sandbox] user's filesystem and network access, only bounded by" >&2
echo "[sandbox] ulimit + a ${TIMEOUT}s timeout. Install Docker for real" >&2
echo "[sandbox] containment before running PoCs from untrusted sources." >&2

run_limited() (
  ulimit -v $((MEM_MB * 1024)) 2>/dev/null
  ulimit -f 65536 2>/dev/null   # 64MB max file writes
  exec "$RUNNER" "$SCRIPT" "$@"
)
export -f run_limited
export RUNNER SCRIPT MEM_MB

if command -v timeout >/dev/null 2>&1; then
  timeout --signal=KILL "${TIMEOUT}s" bash -c 'run_limited "$@"' _ "$@"
else
  run_limited "$@"
fi
