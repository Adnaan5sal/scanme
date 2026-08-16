#!/usr/bin/env bash
# Grep-based first pass for common "vibe coded" production gaps.
# Usage: scan_common_issues.sh [project-root]
#
# This is a starting point, not an oracle. It over-reports (a console.error
# in a real error handler is fine) and under-reports (it can't see logic
# bugs, auth gaps, or N+1 queries). Verify every hit by reading the code.

set -uo pipefail
ROOT="${1:-.}"
cd "$ROOT" || { echo "Cannot cd to $ROOT"; exit 1; }

EXCLUDES=(
  --glob '!node_modules/**' --glob '!.git/**' --glob '!dist/**'
  --glob '!build/**' --glob '!.next/**' --glob '!coverage/**'
  --glob '!vendor/**' --glob '!*.min.js' --glob '!*.lock'
  --glob '!package-lock.json' --glob '!pnpm-lock.yaml' --glob '!yarn.lock'
)

if command -v rg >/dev/null 2>&1; then
  SEARCH() { rg --line-number --no-heading "${EXCLUDES[@]}" "$@" 2>/dev/null; }
else
  echo "NOTE: ripgrep (rg) not found; falling back to grep -r (slower, coarser excludes)."
  SEARCH() {
    local args=() pats=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -e) pats+=("$2"); shift 2 ;;
        -o) args+=(-o); shift ;;
        *)  pats+=("$1"); shift ;;
      esac
    done
    local expr=()
    for p in "${pats[@]}"; do expr+=(-e "$p"); done
    grep -rnE "${args[@]}" --binary-files=without-match \
      --exclude-dir={node_modules,.git,dist,build,.next,coverage,vendor} \
      --exclude={'*.min.js','*.lock','package-lock.json','pnpm-lock.yaml','yarn.lock'} \
      "${expr[@]}" . 2>/dev/null
  }
fi

section() { printf '\n\n=== %s ===\n' "$1"; }

section "Debug artifacts (console.log / debugger / print)"
SEARCH -e 'console\.(log|debug|dir|trace)\(' -e '\bdebugger\b' -e '^\s*print\(' || echo "(none found)"

section "TODO / FIXME / HACK / XXX markers"
SEARCH -e '\b(TODO|FIXME|HACK|XXX)\b' || echo "(none found)"

section "Hardcoded localhost / loopback / absolute local paths"
SEARCH -e 'localhost:[0-9]+' -e '127\.0\.0\.1' -e '0\.0\.0\.0:[0-9]+' \
       -e '/Users/[A-Za-z0-9_.-]+/' -e 'C:\\\\Users\\\\' || echo "(none found)"

section "Possible hardcoded secrets (VERIFY EACH — high false-positive rate)"
SEARCH -e '(api[_-]?key|apikey|secret|password|passwd|token|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{8,}' \
       -e 'sk-[A-Za-z0-9]{16,}' -e 'AKIA[0-9A-Z]{16}' \
       -e 'ghp_[A-Za-z0-9]{20,}' -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' || echo "(none found)"

section "Swallowed errors (empty or log-only catch blocks)"
SEARCH -e 'catch[[:space:]]*\([^)]*\)[[:space:]]*\{[[:space:]]*\}' -e 'except[[:space:]]*:[[:space:]]*pass' || echo "(none found)"

section "Potential XSS sinks"
SEARCH -e 'dangerouslySetInnerHTML' -e 'v-html' -e '\.innerHTML[[:space:]]*=' -e 'document\.write\(' || echo "(none found)"

section "Wildcard CORS"
SEARCH -e 'Access-Control-Allow-Origin.{0,10}\*' -e 'origin[[:space:]]*:[[:space:]]*["'"'"']\*["'"'"']' || echo "(none found)"

section "Env vars referenced in code"
SEARCH -o -e 'process\.env\.[A-Z0-9_]+' -e 'import\.meta\.env\.[A-Z0-9_]+' \
       -e 'os\.environ\[["'"'"'][A-Z0-9_]+["'"'"']\]' \
  | grep -oE '[A-Z][A-Z0-9_]{2,}' | sort -u || echo "(none found)"

section "Config files present"
for f in .env .env.example .env.sample .gitignore .dockerignore Dockerfile \
         package.json tsconfig.json .eslintrc .eslintrc.json eslint.config.js; do
  [ -e "$f" ] && echo "present: $f"
done
[ -d .github/workflows ] && echo "present: .github/workflows/" || echo "MISSING: CI workflows (.github/workflows/)"
{ [ -e .env.example ] || [ -e .env.sample ]; } || echo "MISSING: .env.example"

section "Is .env gitignored?"
if [ -e .gitignore ]; then
  grep -qE '^[[:space:]]*\.env' .gitignore && echo "yes" || echo "NO — .env does not appear in .gitignore"
else
  echo "no .gitignore present"
fi

section "Is .env tracked by git? (critical if yes)"
if [ -d .git ]; then
  tracked=$(git ls-files | grep -E '^\.env($|\.)' || true)
  [ -n "$tracked" ] && echo "TRACKED IN GIT: $tracked" || echo "no .env files tracked"
else
  echo "(not a git repo)"
fi

printf '\n\nScan complete. Every hit above needs human/model verification before acting on it.\n'
