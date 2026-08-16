#!/usr/bin/env bash
# Phase 2 lead generation for scanme.
#
# Usage: find_candidates.sh [project-root]
#
# IMPORTANT: this emits CANDIDATES, not findings. It is a regex pass. It has
# false positives (a `.innerHTML` fed by a constant) and false negatives (it
# cannot see an IDOR, a broken auth model, or a business-logic flaw). Nothing
# printed here may be reported as a vulnerability until Phase 3 proves it.

set -uo pipefail
ROOT="${1:-.}"
cd "$ROOT" || { echo "Cannot cd to $ROOT" >&2; exit 1; }

EX_DIRS=(node_modules .git dist build .next out coverage vendor __pycache__ .venv)
EX_FILES=('*.min.js' '*.map' '*.lock' 'package-lock.json' 'pnpm-lock.yaml' 'yarn.lock')

if command -v rg >/dev/null 2>&1; then
  globs=()
  for d in "${EX_DIRS[@]}"; do globs+=(--glob "!$d/**"); done
  for f in "${EX_FILES[@]}"; do globs+=(--glob "!$f"); done
  SEARCH() { rg --line-number --no-heading --color never "${globs[@]}" "$@" 2>/dev/null; }
else
  SEARCH() {
    local args=() pats=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -e) pats+=("$2"); shift 2 ;;
        -o|-i) args+=("$1"); shift ;;
        *) pats+=("$1"); shift ;;
      esac
    done
    local expr=(); for p in "${pats[@]}"; do expr+=(-e "$p"); done
    local exd=(); for d in "${EX_DIRS[@]}"; do exd+=(--exclude-dir="$d"); done
    local exf=(); for f in "${EX_FILES[@]}"; do exf+=(--exclude="$f"); done
    grep -rnE "${args[@]}" --binary-files=without-match \
      "${exd[@]}" "${exf[@]}" "${expr[@]}" . 2>/dev/null
  }
fi

sec() { printf '\n\n──── %s ────\n' "$1"; }
none() { echo "  (no candidates)"; }

echo "Candidate sweep — LEADS ONLY. Prove or discard each in Phase 3."
echo "Root: $(pwd)"

sec "A. Access control — fetch-by-id without an ownership constraint"
echo "  Review each: does the query scope to the current user?"
SEARCH -e '\.(findById|findByPk|getById)\(' \
       -e 'findOne\(\{\s*(_?id|uuid)\s*:' \
       -e 'WHERE\s+id\s*=' || none

sec "B. Mass assignment — request body spread into a model"
SEARCH -e 'Object\.assign\([^)]*req\.(body|query|params)' \
       -e '\.\.\.\s*req\.(body|query|params)' \
       -e '\.(update|create|insert|save)\([^)]*req\.body' || none

sec "C. SQL — raw query construction / parameterization bypass"
SEARCH -e '(query|execute|exec)\(\s*[`"'"'"'][^`"'"'"']*(SELECT|INSERT|UPDATE|DELETE)' \
       -e '\$queryRawUnsafe|\$executeRawUnsafe|whereRaw|\.raw\(' \
       -e '(SELECT|INSERT INTO|UPDATE|DELETE FROM)[^;]*\$\{' || none

sec "D. Command execution"
SEARCH -e '\b(exec|execSync|spawnSync|execFile)\s*\(' \
       -e 'child_process' -e 'os\.system\(' -e 'subprocess\.(run|call|Popen)' || none

sec "E. HTML sinks (XSS)"
SEARCH -e 'dangerouslySetInnerHTML' -e 'v-html' -e '\.innerHTML\s*=' \
       -e 'document\.write\(' -e 'insertAdjacentHTML' -e '\{\{\{' -e '\|\s*safe' || none

sec "F. DOM XSS sources"
SEARCH -e 'location\.(hash|search|href)' -e 'document\.referrer' \
       -e 'addEventListener\(\s*["'"'"']message["'"'"']' || none

sec "G. eval / dynamic code"
SEARCH -e '\beval\s*\(' -e 'new\s+Function\s*\(' -e 'setTimeout\(\s*["'"'"'`]' \
       -e 'yaml\.load\s*\(' -e 'pickle\.loads' || none

sec "H. Path handling (traversal)"
SEARCH -e 'path\.join\([^)]*req\.' -e 'sendFile\(' -e 'readFile(Sync)?\([^)]*req\.' || none

sec "I. SSRF — outbound request from input-derived URL"
SEARCH -e '(fetch|axios(\.\w+)?|requests\.(get|post))\(\s*[^)]*req\.(body|query|params)' \
       -e '(fetch|axios)\(\s*`?\$\{' || none

sec "J. Secrets in source"
SEARCH -i -e '(api[_-]?key|secret|passwd|password|token|private[_-]?key)\s*[:=]\s*["'"'"'][^"'"'"'$]{12,}' \
       -e 'sk-[A-Za-z0-9]{16,}' -e 'AKIA[0-9A-Z]{16}' -e 'ghp_[A-Za-z0-9]{20,}' \
       -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
       -e 'eyJhbGciOi[A-Za-z0-9_-]{10,}' || none

sec "K. Server secrets on client-exposed env prefixes (HIGH SIGNAL)"
echo "  A service_role / secret key here ships to every browser."
SEARCH -i -e '(NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|TOKEN|PASSWORD|API_KEY)' || none

sec "L. Auth & crypto weaknesses"
SEARCH -e 'algorithms?\s*:\s*\[?\s*["'"'"']none' \
       -e 'jwt\.decode\(' -e 'verify\s*:\s*false' \
       -e 'createHash\(\s*["'"'"'](md5|sha1)' \
       -e 'Math\.random\(\)' \
       -e 'rejectUnauthorized\s*:\s*false' || none

sec "M. CORS / cookies"
SEARCH -e 'Access-Control-Allow-Origin' -e 'origin\s*:\s*(true|["'"'"']\*)' \
       -e 'httpOnly\s*:\s*false' -e 'secure\s*:\s*false' -e 'sameSite\s*:\s*["'"'"']none' || none

sec "N. Supabase / Firebase exposure"
SEARCH -e 'service_role' -e 'createClient\(' \
       -e 'allow read, write: if true' -e 'ENABLE ROW LEVEL SECURITY' || none

sec "O. Git-tracked env files (verify manually)"
if [ -d .git ]; then
  git ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)' || echo "  (none tracked)"
else
  echo "  (not a git repository)"
fi

cat <<'EOF'


────────────────────────────────────────────────────────────
Sweep complete.

Next: Phase 3. For each candidate above, either
  • reproduce it against a local instance (Tier 1), or
  • trace source → sink with no sanitizer, quoting every hop (Tier 2), or
  • discard it, and record why.

Anything you cannot prove is a LEAD, not a finding, and belongs in the
report's appendix — never in the findings section.

This script cannot detect IDOR, broken auth models, or business-logic
flaws. Those require reading the code. Do not treat a clean sweep as a
clean bill of health.
────────────────────────────────────────────────────────────
EOF
