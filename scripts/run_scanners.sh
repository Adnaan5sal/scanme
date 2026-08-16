#!/usr/bin/env bash
# run_scanners.sh - run whatever scanners are available, normalize everything
# through SARIF, and load it into the persistent finding store.
#
# The point is not to be a scanner. It is to be the layer that sits on top of
# whatever the project already runs - Semgrep, CodeQL, Snyk, Trivy, gitleaks -
# and turn a pile of scanner output into tracked findings with identity across
# runs, so "is this new?" and "did our fix hold?" have real answers.
#
#   bash run_scanners.sh [project-root]
#
# Everything it produces is a CANDIDATE. Proof happens in Phase 3.

set -uo pipefail
ROOT="${1:-.}"
OUT="$ROOT/.scanme/scans"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAN=""
SARIF_FILES=()

PY=""
for cand in python3 python py; do
  command -v "$cand" >/dev/null 2>&1 && PY="$cand" && break
done

echo "scanme scanner run - $STAMP"
echo "root: $ROOT"
echo

# -- Semgrep: the highest-value free scanner, AST-based, emits SARIF natively --
if command -v semgrep >/dev/null 2>&1; then
  echo "[semgrep] scanning (security-audit, owasp-top-ten, secrets)..."
  semgrep scan \
    --config p/security-audit \
    --config p/owasp-top-ten \
    --config p/secrets \
    --sarif --output "$OUT/semgrep-$STAMP.sarif" \
    --metrics off --quiet "$ROOT" 2>/dev/null
  if [ -s "$OUT/semgrep-$STAMP.sarif" ]; then
    SARIF_FILES+=("$OUT/semgrep-$STAMP.sarif")
    RAN="$RAN semgrep"
  fi
else
  echo "[semgrep] NOT INSTALLED - this is the biggest coverage gap you can close."
  echo "          pip install semgrep     (free, offline, no account needed)"
fi

# -- gitleaks: committed secrets, including in history -----------------------
if command -v gitleaks >/dev/null 2>&1 && [ -d "$ROOT/.git" ]; then
  echo "[gitleaks] scanning git history for committed secrets..."
  gitleaks detect --source "$ROOT" --report-format sarif \
    --report-path "$OUT/gitleaks-$STAMP.sarif" --no-banner --exit-code 0 2>/dev/null
  if [ -s "$OUT/gitleaks-$STAMP.sarif" ]; then
    SARIF_FILES+=("$OUT/gitleaks-$STAMP.sarif")
    RAN="$RAN gitleaks"
  fi
fi

# -- Trivy: dependency + IaC + container ------------------------------------
if command -v trivy >/dev/null 2>&1; then
  echo "[trivy] scanning filesystem..."
  trivy fs --format sarif --output "$OUT/trivy-$STAMP.sarif" \
    --scanners vuln,secret,misconfig --quiet "$ROOT" 2>/dev/null
  if [ -s "$OUT/trivy-$STAMP.sarif" ]; then
    SARIF_FILES+=("$OUT/trivy-$STAMP.sarif")
    RAN="$RAN trivy"
  fi
fi

# -- Snyk (if the user is already logged in) ---------------------------------
if command -v snyk >/dev/null 2>&1; then
  echo "[snyk] code test..."
  snyk code test "$ROOT" --sarif-file-output="$OUT/snyk-$STAMP.sarif" >/dev/null 2>&1
  if [ -s "$OUT/snyk-$STAMP.sarif" ]; then
    SARIF_FILES+=("$OUT/snyk-$STAMP.sarif")
    RAN="$RAN snyk"
  fi
fi

# -- Bandit for Python -------------------------------------------------------
if command -v bandit >/dev/null 2>&1 && ls "$ROOT"/*.py >/dev/null 2>&1; then
  echo "[bandit] scanning python..."
  bandit -r "$ROOT" -f sarif -o "$OUT/bandit-$STAMP.sarif" -q 2>/dev/null
  [ -s "$OUT/bandit-$STAMP.sarif" ] && SARIF_FILES+=("$OUT/bandit-$STAMP.sarif") && RAN="$RAN bandit"
fi

# -- Dependency audits (not SARIF; ingested through their own normalizer) ----
NPM_AUDIT=""
if [ -f "$ROOT/package.json" ] && command -v npm >/dev/null 2>&1; then
  echo "[npm audit] checking dependencies..."
  (cd "$ROOT" && npm audit --json > "$OUT/npm-$STAMP.json" 2>/dev/null)
  [ -s "$OUT/npm-$STAMP.json" ] && NPM_AUDIT="$OUT/npm-$STAMP.json" && RAN="$RAN npm-audit"
fi

if command -v pip-audit >/dev/null 2>&1 && \
   { [ -f "$ROOT/requirements.txt" ] || [ -f "$ROOT/pyproject.toml" ]; }; then
  echo "[pip-audit] checking dependencies..."
  (cd "$ROOT" && pip-audit --format sarif -o "$OUT/pipaudit-$STAMP.sarif" 2>/dev/null)
  [ -s "$OUT/pipaudit-$STAMP.sarif" ] && SARIF_FILES+=("$OUT/pipaudit-$STAMP.sarif") && RAN="$RAN pip-audit"
fi

echo

# -- Regex sweep for the classes AST scanners systematically miss ------------
# IDOR, mass assignment, and client-exposed env prefixes are structural/semantic
# rather than syntactic, so generic rulesets rarely catch them.
if [ -f "$HERE/find_candidates.sh" ]; then
  echo "[regex sweep] IDOR / mass-assignment / client-exposed secrets..."
  bash "$HERE/find_candidates.sh" "$ROOT" > "$OUT/regex-$STAMP.txt" 2>/dev/null
  echo "             -> $OUT/regex-$STAMP.txt (read this manually; not auto-ingested)"
  echo
fi

# -- Load everything into the store ------------------------------------------
if [ -z "$PY" ]; then
  echo "No Python found - cannot load the finding store."
  echo "Raw scanner output is in $OUT/"
  exit 0
fi

if [ ${#SARIF_FILES[@]} -eq 0 ] && [ -z "$NPM_AUDIT" ]; then
  echo "No scanner produced output. Install at least Semgrep:"
  echo "  pip install semgrep"
  exit 0
fi

LABEL="${SCAN_LABEL:-scan $STAMP}"

if [ ${#SARIF_FILES[@]} -gt 0 ]; then
  # Merge every scanner's SARIF into one normalized set first, so the same
  # issue found by two tools becomes one finding rather than two.
  "$PY" "$HERE/sarif.py" "${SARIF_FILES[@]}" --json > "$OUT/merged-$STAMP.json"
  "$PY" "$HERE/findings.py" --root "$ROOT" ingest "$OUT/merged-$STAMP.json" --label "$LABEL"
fi

if [ -n "$NPM_AUDIT" ]; then
  # --no-close because a dependency scan says nothing about code findings;
  # letting it close them would silently mark real issues as gone.
  "$PY" "$HERE/findings.py" --root "$ROOT" ingest "$NPM_AUDIT" --label "$LABEL deps" --no-close
fi

echo
echo "scanners run:$RAN"
echo
"$PY" "$HERE/findings.py" --root "$ROOT" stats
echo
echo "Next:"
echo "  findings.py list --status candidate --severity critical   # triage"
echo "  findings.py diff                                          # what changed"
echo "  findings.py show <id>                                     # detail + history"
echo
echo "Everything above is a CANDIDATE. Prove it (Phase 3) before it becomes a finding."
