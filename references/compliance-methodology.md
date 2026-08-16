# Audit methodology — sampling, evidence standards, materiality

Used by Compliance Mode. This file answers the question a compliance
professional would ask: "How did you decide what to test, what counts as
passing, and what's worth reporting?" Without documented answers, a PASS is
meaningless.

---

## Population and sampling

The audit population is everything in scope. Sampling is the subset actually
examined. The gap between them is audit risk.

### Endpoint sampling

| Population size | Minimum sample | Selection method |
|---|---|---|
| ≤20 endpoints | All | Exhaustive |
| 21–100 | 20 + all high-risk | Stratified by auth requirement and data sensitivity |
| 101–500 | 40 + all high-risk | Stratified + random |
| 500+ | 60 + all high-risk | Stratified + random; note coverage is partial |

**High-risk endpoints — always test regardless of sample size:**
- Authentication and session routes (`/login`, `/logout`, `/reset-password`)
- Payment and subscription operations
- Admin and privileged-access routes
- Any endpoint that returns another user's data by ID
- File upload and download handlers
- Webhook receivers

Document which endpoints were sampled. A clean result on a 10% sample doesn't
mean the other 90% is clean — say so.

### Code sampling for injection and input handling

1. All files that handle request input directly (controllers, route handlers)
2. All files that write to a database or execute system commands
3. A random 10% of remaining files for spot-check

Run `scripts/run_scanners.sh` first — AST-based coverage across all files
faster than manual reading. Manual reading then focuses on scanner findings
plus the high-risk categories above.

### Authorization: sample by role, not just endpoint

Minimum required:
- One anonymous request per protected endpoint
- One authenticated-but-unauthorized request (user A accessing user B's
  resource) for every endpoint that takes a resource ID
- One privileged-account request for every admin-protected endpoint

Document which role-endpoint combinations were not tested.

---

## Evidence standards

**PASS** — you examined the relevant code or config and found the control
implemented. Quote it: `auth.js:47 — ownership check: findOne({_id, userId})`.
Do not mark PASS based on framework assumptions or general impression.

**FAIL** — specific gap with specific location. Quote it:
`orders.js:112 — findById with no ownership check; returns any user's order`.
Include severity with reasoning.

**PARTIAL** — control partially implemented. Name which paths are covered and
which aren't: "Rate limiting present on /api/login (pass) but absent on
/api/auth/google/callback (gap)."

**NOT TESTED** — you did not examine this area. State what evidence would
close it. NOT TESTED ≠ PASS.

**N/A** — genuinely inapplicable. State the reason.

**Never mark PASS because:**
- The framework probably handles it
- You didn't see evidence it was broken
- It wasn't in scope but you'd expect it to be fine

---

## Materiality thresholds

### CRITICAL — blocks production, no exceptions

- Exploitable without authentication
- Direct path to: all user data, account takeover, RCE, payment fraud
- Hardcoded production secrets in committed code
- SQL/command injection reachable from a public endpoint

### HIGH — blocks production unless formally risk-accepted

- Exploitable by any authenticated user
- Path to: another user's private data, privilege escalation, session hijacking
- Missing rate limiting on authentication endpoints
- Missing CSRF protection on state-changing operations

### Escalation rules — raise severity by one level when:

- High-traffic or customer-facing endpoint (vs internal/rarely used)
- Application handles sensitive data (health, financial, personal comms)
- Finding chains with another finding for higher impact
- No incident-response procedure exists (slower recovery = higher effective risk)

### Stays LOW or INFORMATIONAL despite appearing in the checklist:

- Missing defense-in-depth headers when the underlying vulnerability is absent
  (no XSS → missing CSP is informational, not high)
- Dependency vulnerabilities where the code path is not reachable
- Governance gaps in an early-stage internal tool with no external users
- Confirmable items where the user says a control exists but evidence isn't
  available — NOT TESTED, not FAIL

---

## Reporting completeness standard

Before closing the audit, confirm:

1. Every section has a status (PASS / FAIL / PARTIAL / N/A / NOT TESTED)
2. Every FAIL and PARTIAL has: location, evidence quote, severity
   justification, remediation action
3. Every NOT TESTED has a note on what evidence would close it
4. The final production gate is accurate — no CLEAR gate items when a
   CRITICAL or HIGH finding is open in that area
5. "Auditor" and "Date" fields are filled — an undated report cannot serve
   as evidence that a state existed at a point in time

The most important section for a future reader is often what was NOT TESTED
and why. An audit report that omits what it didn't cover is not honest.

---

## Prior audit continuity

At the start of every compliance audit, check for an existing
`SECURITY_AUDIT.md` and the finding store (`python scripts/findings.py
stats`) before doing anything else — same Phase 0 discipline as Audit Mode.
Previously PASS items get spot-checked, not fully re-verified, unless
significant time has passed or the codebase changed substantially in that
area. Previously FAIL items: verify whether the fix landed. Previously NOT
TESTED items: prioritize closing these if evidence is now available.
