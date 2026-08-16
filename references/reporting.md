# Phase 5 — The report

Save as `SECURITY_AUDIT.md` in the project root unless the user says otherwise.

The report's job is to be **trusted and acted on**. That means every claim
carries its evidence, and the boundary between "proven" and "suspected" is
impossible to miss.

## Format

````markdown
# Security Audit — <project>

**Date:** <date>
**Commit:** <git rev-parse --short HEAD>
**Method:** Verified audit — every finding below was reproduced or traced
end-to-end. Unconfirmed leads are in the appendix, separated deliberately.

## Summary

| | |
|---|---|
| Proven vulnerabilities | **N** (Critical N · High N · Medium N · Low N) |
| Fixed and regression-tested | **N** |
| Reported, not fixed | **N** |
| Unverified leads (appendix) | N |
| Candidates investigated and discarded | N |

<Two or three sentences: the most serious thing found, whether it's fixed,
and what the user should do first. If nothing was proven, say that plainly —
and say equally plainly that it doesn't mean the app is secure.>

## Findings at a glance

Every proven finding in one scannable table, severity-ordered. Most readers
will read only this table — it must stand alone, so "what I did" has to be
concrete ("Parameterized query + test") rather than a bare status word.

| ID | Severity | Finding | Location | Proof | What I did |
|---|---|---|---|---|---|
| SEV-01 | Critical | Any user can read any order | `routes/orders.js:47` | Tier 1 — reproduced | **Fixed** — scoped query to owner, regression test added (red→green) |
| SEV-02 | High | Password reset token never expires | `auth/reset.js:23` | Tier 1 — reproduced | **Reported** — needs a token-lifetime decision |
| SEV-03 | Medium | CDN scripts lack integrity checks | `index.html:67` | Tier 2 — traced | **Fixed** — SRI hashes added, load verified |

Then a second table for anything you changed that isn't a numbered finding —
so the reader can account for every file you touched:

| File | Change | Reason | Backup |
|---|---|---|---|
| `.gitignore` | added `.env` | was tracked | n/a |

Never let a modified file go unlisted. A reader who finds an unexplained diff
stops trusting the whole report.

## Scope

- **Audited:** <entry points examined, e.g. "23 of 23 API routes, 4 client
  data flows, auth middleware, Supabase RLS policies">
- **Not audited:** <what you couldn't cover and why — "the payments webhook
  handler; requires Stripe test credentials">
- **Environment:** <ran locally / static review only>

---

## Findings

### [SEV-01] Critical — Any authenticated user can read any order

**Location:** `src/routes/orders.js:47`
**Class:** Broken access control (IDOR)
**Status:** Fixed · regression test added

**Impact**
Any logged-in account can read every order in the system by incrementing an
ID — customer names, addresses, emails, and line items. Order IDs are
sequential, so full-database extraction is a trivial loop.

**Proof (Tier 1 — reproduced)**
```
Authenticated as userA (id=1).

GET /api/orders/2
Authorization: Bearer <userA token>

200 OK
{"id":2,"userId":2,"email":"userb@test.local","address":"..."}
```
Order 2 belongs to userB. userA received it in full.

**Root cause**
```js
// src/routes/orders.js:47 — fetched by id alone; ownership never checked
const order = await Order.findById(req.params.id);
```

**Fix applied**
```js
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
if (!order) return res.status(404).json({ error: 'Not found' });
```
Returns 404 rather than 403 so the endpoint doesn't confirm which IDs exist.

**Regression test**
`tests/security/orders.access.test.js::rejects reading another user's order`
Failed before the fix (returned 200 with userB's data), passes after. Full
suite: 48/48 passing.
````

Repeat per finding, severity-ordered. Keep every section — a finding without
proof isn't a finding, and a fix without its test result isn't verified.

For findings you did **not** fix, replace the last two sections with:

```markdown
**Recommended fix (not applied)**
<the patch>

**Why not applied**
<e.g. "Changing the password hashing algorithm invalidates all stored
credentials and requires a migration plan for existing users.">
```

---

## Appendix A — Unverified leads

State the framing explicitly:

> These are **not confirmed vulnerabilities.** Each is something that looked
> suspicious but that I could not confirm. Listed so you can check them with
> context I don't have.

Per lead: location, what looked suspicious, **what specifically blocked
confirmation**, and how the user could check in one step.

## Appendix B — Investigated and discarded

Brief, but valuable — it shows the work and stops the next scan from
re-raising the same noise.

| Location | Why it looked suspicious | Why it isn't exploitable |
|---|---|---|
| `views/profile.ejs:12` | `<%- bio %>` unescaped output | `bio` is sanitized by `sanitizeHtml()` at `models/user.js:88` before persistence |

## Appendix C — Dependencies

Advisory counts by severity, then — separately — which are actually reachable
from application code. Say which were patched and confirm the suite still
passes.

## Limitations

Restate honestly:

> This is a source-code audit, not a penetration test. It does not cover
> infrastructure, network, TLS, or cloud IAM configuration. **No proven
> findings does not mean no vulnerabilities exist** — it means none were
> proven within this scope.

## Writing rules

- **Never state a suspicion in the findings section.** If hedging words are
  creeping in — "could potentially", "may be vulnerable" — it belongs in
  Appendix A.
- **Quote real output**, not paraphrase. Redact real user data; use test-account
  values.
- **Justify severity in the impact text** — what an attacker gets, how easily.
  Don't just assert a label.
- **Lead with the worst thing.** If something is critical and unfixed, say it in
  the first line of the chat summary, not just in the file.
- **Keep it short enough to be read.** Five proven findings with real evidence
  will change behavior; sixty pages will not.
