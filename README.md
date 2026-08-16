# scanme

**A Claude Code skill that only reports vulnerabilities it can prove — and fixes them with a regression test that fails before the fix and passes after.**

The name is a dare, not an invitation: this audits code *you* control, never a live site you don't own or haven't been authorized to test. See [Scope and authorization](SKILL.md#scope-and-authorization).

Most security scanners hand you 200 findings. You check the first five, four are wrong, and you stop reading. The real vulnerability was #47.

This one works the opposite way. Every candidate must be **reproduced or traced end to end** before it's allowed to be called a finding. Anything unproven gets demoted to an appendix and labelled as unconfirmed. You get fewer findings — and you can act on all of them.

---

## See it work — 20 seconds, no install

```bash
git clone https://github.com/Adnaan5sal/scanme
cd scanme/demo/vulnshop
bash run_demo.sh
```

Node 22.5+ and Python 3. No `npm install` — the demo app has zero dependencies.

It runs against `vulnshop`, a small order API with real auth, a real database,
and two critical vulnerabilities. Here is what actually comes out:

**Semgrep, 225 rules, finds nothing:**

```
semgrep scanned ['server.js'] with 225 rules
semgrep findings: 0
```

**scanme proves an IDOR by exploiting it** — Bob reads Alice's order:

```
Bob (user 2) requests Alice's order 4471:
{"id":4471,"user_id":1,"item":"Noise-cancelling headphones",
 "total":349.99,"card_last4":"4242"}      -> HTTP 200

unauthenticated control:
{"error":"Unauthorized"}                  -> HTTP 401
```

That 401 is the point: authentication works, **authorization was never
implemented**.

**The regression test goes red before the fix exists:**

```
AssertionError: Bob received HTTP 200 for Alice's order - expected 404
```

**Then green after it, with legitimate access intact** — `404` for Alice's
order, `200` for Bob's own. 8/8 tests pass.

**And weeks later, when a refactor silently drops the fix:**

```
REGRESSED:  1  <-- previously fixed, now back

!! idor4471  critical regressed  T1 server.js:137
 + sqli0sea  critical fixed      T1 server.js:155
```

Only the IDOR is flagged. The SQL injection stays `fixed`, because it never
came back. **That's the thing a Markdown report can't do** — a security fix
that silently reverts is the most dangerous state a codebase can reach, because
everyone believes it's closed.

📄 **[Full case study, every command and output →](demo/README.md)**

---

## The two rules

**1. A finding does not exist until it's proven.**

Every candidate must reach one of these bars:

| Tier | Standard |
|---|---|
| **1 — Reproduced** | The vulnerability is actually triggered against a local instance and observed. Request in, exploited response out. |
| **2 — Traced** | Attacker-controlled source → every hop → dangerous sink, each quoted, with no sanitizer anywhere along the path. |
| **3 — Unproven** | **Not a vulnerability.** Goes to the appendix with a note on exactly what blocked confirmation. |

**2. A fix isn't done until the test proves it.**

```
1. Write the regression test encoding the exploit
2. Run it on the vulnerable code  →  MUST FAIL
3. Apply the fix
4. Run it again                   →  MUST PASS
5. Run the full suite             →  nothing else broke
```

Step 2 is the one everyone skips. A test that was never seen to fail might be asserting something that was always true — you'd ship a fix "covered" by a test that catches nothing. Watching it go red first is the only proof the test can detect the bug at all.

If any step can't complete, **the fix isn't applied.** You get the patch and an honest explanation instead.

---

## What you get back

Every report opens with a table you can read in ten seconds — what was found, how it was proven, and what was actually done about it:

| ID | Severity | What I found | Location | Proof | What I did |
|---|---|---|---|---|---|
| SEV-01 | Critical | Any user can read any order | `routes/orders.js:47` | Tier 1 — reproduced | **Fixed** — query scoped to owner; regression test red→green |
| SEV-02 | High | Password reset token never expires | `auth/reset.js:23` | Tier 1 — reproduced | **Reported** — needs a token-lifetime decision |
| SEV-03 | Medium | CDN scripts lack integrity checks | `index.html:67` | Tier 2 — traced | **Fixed** — SRI hashes added, load verified |

Followed by a second table accounting for **every file touched**, with backups — so no diff in your working tree is unexplained.

Then the full write-up per finding:

## What a finding looks like

> ### [SEV-01] Critical — Any authenticated user can read any order
>
> **Location:** `src/routes/orders.js:47` · **Class:** IDOR · **Status:** Fixed · regression test added
>
> **Impact** — Any logged-in account can read every order by incrementing an ID: names, addresses, emails, line items. IDs are sequential, so full extraction is a trivial loop.
>
> **Proof (Tier 1 — reproduced)**
> ```
> Authenticated as userA (id=1).
> GET /api/orders/2   Authorization: Bearer <userA token>
>
> 200 OK
> {"id":2,"userId":2,"email":"userb@test.local","address":"..."}
> ```
> Order 2 belongs to userB. userA received it in full.
>
> **Root cause**
> ```js
> const order = await Order.findById(req.params.id);  // ownership never checked
> ```
>
> **Fix applied**
> ```js
> const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
> if (!order) return res.status(404).json({ error: 'Not found' });
> ```
> 404 rather than 403, so the endpoint doesn't confirm which IDs exist.
>
> **Regression test** — `tests/security/orders.access.test.js` · failed before the fix (200 with userB's data), passes after · full suite 48/48.

---

## Install

```bash
npx skills add https://github.com/Adnaan5sal/scanme --agent claude-code -g
```

Or drop the folder into `~/.claude/skills/`.

## Use

```
/scanme
```

Or just describe what you want — "audit this before I launch", "find security holes in my app", "which of these scanner findings are real?"

---

## What it hunts

Ordered by how often these turn out to be real *and* serious in AI-assisted codebases:

1. **Broken access control (IDOR)** — the #1 miss, because vulnerable code looks completely normal. Authentication answers *who are you*, not *may you touch this*.
2. **Exposed secrets** — including the vibe-coding classic: a Supabase `service_role` key on a `NEXT_PUBLIC_` prefix, shipped to every browser.
3. **Injection** — SQL, NoSQL (`{"$ne": null}` auth bypass), command, template, path traversal.
4. **XSS** — reflected, stored, DOM-based, and `javascript:` URLs that HTML-escaping doesn't stop.
5. **Auth weaknesses** — `alg: none`, unverified JWTs, `Math.random()` tokens, dev backdoors left reachable.
6. **SSRF** — especially cloud metadata endpoints.
7. **Misconfiguration** — CORS, cookie flags, leaked stack traces.
8. **Dependencies** — filtered by whether the vulnerable path is *actually reachable*, not raw `npm audit` output.

---

## Also does

The proof-tiered audit above is the core, but everything below shares its
proof discipline and its finding store — one audit trail per project, not a
pile of differently-formatted documents.

| Ask for... | You get |
|---|---|
| Guardrails while you build auth/API/payment code | **Guard Mode** — inline while writing, or `bash scripts/install_guard.sh` for a permanent hook |
| A compliance / SOC 2 / PCI DSS readiness pass | **Compliance Mode** — 35 sections, tagged `[code]`/`[confirm]`/`[specialist]`, with sampling strategy and materiality thresholds, not just a checklist |
| "Is my AI app secure" | **AI Security Mode** — indirect prompt injection, RAG tenant isolation, agent/tool sandboxing, cost abuse |
| Security headers / CSP | **Headers Mode** — inventories what the app actually loads before writing a policy |
| A standing security test suite | **Test Generation** — the authorization-matrix pattern, wired into CI |
| "Make this production ready" (beyond security) | **Readiness Mode** — error handling, performance, deploy config, accessibility, dependency health |

Full routing table and detail in [SKILL.md](SKILL.md).

---

## What it deliberately won't do

Stated up front, because a security tool that overstates its coverage is worse than none:

- **It's a code audit, not a penetration test.** No infrastructure, network, TLS, or cloud IAM.
- **It cannot prove absence.** "No proven findings" means exactly that — not "your app is secure."
- **It won't touch crypto, auth architecture, or business logic on its own.** Changing a hashing algorithm can lock out every user. It reports those with a recommendation and lets you decide.
- **It only audits code you control.** Point it at your repo or your local instance. It will refuse to actively probe a domain you haven't confirmed you own — unauthorized scanning is your legal problem, not a thoroughness win.

---

## Why "fewer findings" is the feature

False positives don't just waste an afternoon. They train developers to skim security output, which means the one real vulnerability in the list gets skimmed too. Precision isn't a nicety here — it's the whole mechanism by which a security report changes behavior.

So this skill is built to be **boring and trustworthy**: it discards aggressively, records *why* it discarded each candidate, and separates "I proved this" from "this looked odd" with a wall you can't accidentally read past.

---

## License

MIT
