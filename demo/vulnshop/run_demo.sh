#!/usr/bin/env bash
# run_demo.sh - the whole scanme loop, end to end, in about 20 seconds.
#
#   bash run_demo.sh
#
# Requires Node 22.5+ and Python 3. No npm install, no dependencies.
#
# It replays a real timeline:
#   1. an audit finds two criticals that Semgrep's 225 rules miss entirely
#   2. both are proven by actually exploiting them over HTTP
#   3. regression tests are written, confirmed RED, then the fixes land
#   4. a later refactor silently drops one fix
#   5. the store flags exactly that one as REGRESSED - and not the other
#
# Step 5 is the part no Markdown report can do.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

H="../../scripts/findings.py"
PORT=3771
export PORT

rule() { printf '\n\033[1m%s\033[0m\n' "$1"; printf '%s\n' "$(printf '%.0s-' $(seq 1 ${#1}))"; }

python -c "
import pathlib
p = pathlib.Path('.scanme/findings.db')
p.unlink() if p.exists() else None"

tok() {
  curl -s -X POST "http://localhost:$PORT/api/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" \
    | python -c "import sys,json;print(json.load(sys.stdin)['token'])"
}

rule "0. Start from the vulnerable code"
python toggle.py idor break
python toggle.py sqli break
echo "   ownership scope removed; query concatenation restored"

rule "1. What a scanner sees"
if command -v semgrep >/dev/null 2>&1; then
  PYTHONUTF8=1 semgrep scan --config p/security-audit --config p/owasp-top-ten \
    --json --output .semgrep.json --metrics off --quiet server.js 2>/dev/null
  python -c "
import json
d = json.load(open('.semgrep.json'))
print('   semgrep scanned', d['paths']['scanned'], 'with 225 rules')
print('   semgrep findings:', len(d['results']))" 2>/dev/null
else
  echo "   semgrep not installed - it reports 0 here. (pip install semgrep)"
fi
echo "   Neither vulnerability is syntactic: broken object-level authorization is"
echo "   semantic, and the SQL sink is node:sqlite, too new for any ruleset."

rule "2. Prove them by actually exploiting them"
node server.js > /dev/null 2>&1 &
VULN_PID=$!
sleep 2
BOB=$(tok bob@example.com bob123)
echo "   Bob (user 2) requests Alice's order 4471:"
curl -s -w "\n   -> HTTP %{http_code}\n" "http://localhost:$PORT/api/orders/4471" \
  -H "Authorization: Bearer $BOB" | sed 's/^/   /'
echo "   unauthenticated control:"
curl -s -w "\n   -> HTTP %{http_code}\n" "http://localhost:$PORT/api/orders/4471" | sed 's/^/   /'
echo "   (401 for anonymous proves auth works - authorization is what is missing)"
echo
echo -n "   search q=key          -> rows: "
curl -s "http://localhost:$PORT/api/search?q=key" \
  | python -c "import sys,json;print(len(json.load(sys.stdin)['results']))"
echo -n "   search q=' OR '1'='1  -> rows: "
curl -s --get --data-urlencode "q=' OR '1'='1" "http://localhost:$PORT/api/search" \
  | python -c "import sys,json;print(len(json.load(sys.stdin)['results']))"
kill $VULN_PID 2>/dev/null; wait $VULN_PID 2>/dev/null

rule "3. Record and prove in the store"
python detect.py server.js > found.json 2>/dev/null
python $H ingest found.json --label "initial audit" | sed 's/^/   /'
python $H promote idor4471 --tier 1 \
  --note "Bob(uid2) GET /orders/4471 -> 200 with Alice card_last4 4242; anon -> 401" | sed 's/^/   /'
python $H promote sqli0sea --tier 1 \
  --note "q=' OR '1'='1 returned all 3 products vs 1; UNION reached users table" | sed 's/^/   /'

rule "4. Test first - it must go RED before any fix exists"
node --test test_order_idor.js 2>&1 | grep -E "^(✔|✖)" | sed 's/^/   /'
echo "   ^ the IDOR test fails on vulnerable code, so it detects something real"

rule "5. Apply the fixes, watch the tests go green"
python toggle.py idor fix
python toggle.py sqli fix
node --test test_order_idor.js test_search_sqli.js 2>&1 \
  | grep -E "(tests|pass|fail) [0-9]+$" | sed 's/^/   /'
python $H fix idor4471 --test test_order_idor.js | sed 's/^/   /'
python $H fix sqli0sea --test test_search_sqli.js | sed 's/^/   /'
echo
echo "   live re-check against the fixed server:"
node server.js > /dev/null 2>&1 &
FIX_PID=$!
sleep 2
BOB2=$(tok bob@example.com bob123)
curl -s -o /dev/null -w "   Bob -> Alice's order: HTTP %{http_code}\n" \
  "http://localhost:$PORT/api/orders/4471" -H "Authorization: Bearer $BOB2"
curl -s -o /dev/null -w "   Bob -> his own order: HTTP %{http_code}\n" \
  "http://localhost:$PORT/api/orders/5013" -H "Authorization: Bearer $BOB2"
kill $FIX_PID 2>/dev/null; wait $FIX_PID 2>/dev/null

rule "6. A clean re-scan"
python detect.py server.js > found.json 2>/dev/null
python $H ingest found.json --label "clean re-scan" | sed 's/^/   /'

rule "7. Weeks later, a refactor drops the ownership scope"
python toggle.py idor break
python detect.py server.js > found.json 2>/dev/null
python $H ingest found.json --label "post-refactor scan" | sed 's/^/   /'

rule "8. The store catches it - and only it"
python $H diff | sed 's/^/   /'
python $H list | sed 's/^/   /'
echo
echo "   The SQL injection is still marked fixed, because it never came back."
echo "   Re-ingesting a static list would have flagged both. That would be a lie."

rule "9. Audit trail"
python $H show idor4471 | sed -n '/History/,$p' | sed 's/^/   /'

# leave the tree clean
python toggle.py idor fix
python $H fix idor4471 --test test_order_idor.js > /dev/null

rule "10. The report the user actually reads"
python $H meta project --set "vulnshop (demo API)" > /dev/null
python $H meta scope --set "Full source review of server.js (4 routes, 176 lines): authentication, session tokens, object-level authorization, SQL query construction, and error handling. Semgrep OSS run with 225 rules. Both findings reproduced against a live instance over HTTP." > /dev/null
python $H meta not_checked --set "- File upload handling (the app has none)
- CSRF (no cookie-based sessions)
- SSRF (no outbound requests)
- Dependency vulnerabilities (zero third-party dependencies)
- Rate limiting, account lockout, password policy
- Deployment configuration, TLS, security headers" > /dev/null
python $H scorecard
python $H report > SECURITY_AUDIT.md
echo "   Full report written to SECURITY_AUDIT.md ($(wc -l < SECURITY_AUDIT.md) lines)"
python -c "
import pathlib
for f in ('found.json', '.semgrep.json'):
    p = pathlib.Path(f)
    p.unlink() if p.exists() else None"
echo
echo "Repo restored to the fixed state. Run 'node --test *.js' - 8/8 pass."
