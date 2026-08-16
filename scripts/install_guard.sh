#!/usr/bin/env bash
# install_guard.sh - wire Guard Mode as a PreToolUse hook.
#
# Without this, Guard Mode only engages when a request happens to match the
# skill description. With it, every Write/Edit is inspected by guard.py
# and the specific guardrail for whatever pattern it finds is injected into
# context - including on edits that were never framed as "build a feature",
# which is exactly where guardrails otherwise get skipped.
#
# The hook is advisory. It never blocks a tool call and fails open on any error.
#
# Run once:   bash install_guard.sh
# Undo:       bash install_guard.sh --uninstall

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/guard.py"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
MARKER="guard.py"

# -- locate an interpreter: python3 is absent on many Windows installs --------
PY=""
for cand in python3 python py; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c "import sys; sys.exit(0 if sys.version_info>=(3,6) else 1)" 2>/dev/null; then
      PY="$cand"
      break
    fi
  fi
done

if [ -z "$PY" ]; then
  echo "No Python 3.6+ found on PATH (tried python3, python, py)." >&2
  echo "The fast pass still works without this hook; only the automatic" >&2
  echo "per-edit Guard Mode needs it." >&2
  exit 1
fi

if [ ! -f "$GUARD" ]; then
  echo "Cannot find $GUARD - run this script from scanme's scripts/ dir." >&2
  exit 1
fi

# Smoke-test before installing anything. A hook that errors on every edit is
# worse than no hook, so prove it runs first.
if ! echo '{"tool_name":"Write","tool_input":{"file_path":"x.js","content":"var a=1;"}}' \
     | "$PY" "$GUARD" >/dev/null 2>&1; then
  echo "guard.py failed its smoke test - not installing." >&2
  exit 1
fi

# On Windows, $GUARD is an MSYS path (/c/Users/...) which only Git Bash can
# resolve. cygpath -m gives C:/Users/... which works from any shell.
GUARD_PORTABLE="$GUARD"
if command -v cygpath >/dev/null 2>&1; then
  GUARD_PORTABLE="$(cygpath -m "$GUARD")"
fi

HOOK_CMD="$PY \"$GUARD_PORTABLE\""

mkdir -p "$(dirname "$SETTINGS")"
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"

MODE="install"
[ "${1:-}" = "--uninstall" ] && MODE="uninstall"

"$PY" - "$SETTINGS" "$HOOK_CMD" "$MARKER" "$MODE" <<'PYEOF'
import json, shutil, sys

path, cmd, marker, mode = sys.argv[1:5]

try:
    with open(path, encoding="utf-8") as f:
        settings = json.load(f)
except (ValueError, OSError):
    print("settings.json is not valid JSON - refusing to touch it.", file=sys.stderr)
    sys.exit(1)

hooks = settings.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])

def is_ours(entry):
    return any(marker in (h.get("command") or "") for h in entry.get("hooks", []))

if mode == "uninstall":
    kept = [e for e in pre if not is_ours(e)]
    if len(kept) == len(pre):
        print("No scanme guard hook installed - nothing to remove.")
        sys.exit(0)
    hooks["PreToolUse"] = kept
else:
    if any(is_ours(e) for e in pre):
        print("Guard hook already installed - refreshing its command path.")
        for e in pre:
            if is_ours(e):
                for h in e["hooks"]:
                    if marker in (h.get("command") or ""):
                        h["command"] = cmd
    else:
        pre.append({
            "matcher": "Write|Edit|MultiEdit",
            "hooks": [{"type": "command", "command": cmd, "timeout": 10}],
        })

# Back up before writing - settings.json holds the user's whole config.
try:
    shutil.copyfile(path, path + ".scanme-backup")
except OSError:
    pass

with open(path, "w", encoding="utf-8") as f:
    json.dump(settings, f, indent=2)

print("{} scanme guard hook in {}".format(
    "Removed" if mode == "uninstall" else "Installed", path))
print("Previous settings backed up to {}.scanme-backup".format(path))
PYEOF

if [ "$MODE" = "install" ]; then
  cat <<EOF

Guard Mode is live. Every Write/Edit now runs a fast pattern check for:
  IDOR / missing ownership scope     SQL + command injection
  plaintext passwords                mass assignment
  XSS sinks                          hardcoded + client-exposed secrets
  wildcard CORS                      error leakage
  missing cookie flags               unpinned JWT algorithms
  path traversal                     SSRF
  eval                               NoSQL auth bypass

It stays silent unless something matches, and it can never block an edit.
Restart Claude Code for the hook to take effect.

Remove with:  bash "$HERE/install_guard.sh" --uninstall
EOF
fi
