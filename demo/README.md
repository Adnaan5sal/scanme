# Case study: two criticals a scanner can't see

Everything below was produced by an actual run. Reproduce it yourself:

```bash
cd demo/vulnshop
bash run_demo.sh
```

Requires Node 22.5+ and Python 3. **No `npm install`** — `vulnshop` uses
`node:sqlite`, `node:http`, and `node:test`, all built in. Takes about 20
seconds.

---

## The target

`vulnshop` is a small order-management API: login, view your orders, search
products. Real auth (HMAC-signed tokens), a real database, two real users. It
is written the way an AI-assisted project actually comes out — not as a CTF
puzzle with a flag hidden in it.

It has two critical vulnerabilities. Both look completely ordinary in review.

## Step 1 — What the scanner found

```
semgrep scanned ['server.js'] with 225 rules
semgrep findings: 0
```

Zero. Semgrep works fine — pointed at a canary file containing
`eval(req.query.code)` it flags it immediately. It misses these two for
structural reasons:

- **The IDOR is semantic.** No generic rule can know that `orders.user_id` is
  supposed to equal the session user. Broken object-level authorization is the
  most common serious web vulnerability, and static rulesets essentially never
  find it, because the rule would have to understand your data model.
- **The SQL sink is `node:sqlite`.** Rulesets know `mysql`, `pg`, `sequelize`.
  `DatabaseSync.prepare()` shipped in Node 22.5 and no ruleset covers it yet.
  New API, same ancient bug, invisible.

This is the gap scanme exists to fill. Run your scanners — scanme ingests their
SARIF — but understand what they structurally cannot see.

## Step 2 — Proof, not suspicion

A finding does not exist until it has been demonstrated. Both were proven at
**Tier 1**: executed against a running instance, not argued from source.

**IDOR** — Bob (user 2) requests Alice's order:

```
Bob (user 2) requests Alice's order 4471:
{"id":4471,"user_id":1,"item":"Noise-cancelling headphones",
 "total":349.99,"card_last4":"4242"}
   -> HTTP 200

unauthenticated control:
{"error":"Unauthorized"}
   -> HTTP 401
```

The control request is what makes this airtight. Anonymous access returns 401,
so authentication works. It is *authorization* that was never implemented — and
that distinction is the entire finding. Bob receives Alice's item, total, and
card digits.

**SQL injection** — one payload, two very different result counts:

```
search q=key          -> rows: 1
search q=' OR '1'='1  -> rows: 3
```

A `UNION SELECT id, email, id FROM users --` payload reaches the users table.

## Step 3 — The test goes red first

```
✔ the owner can read their own order
✔ anonymous requests are rejected
✖ a user CANNOT read another user's order
✔ legitimate access still works after the fix
```

Written **before** the fix and confirmed failing:

```
AssertionError: Bob received HTTP 200 for Alice's order - expected 404
  200 !== 404
```

This step is not ceremony. A security test that has never failed is not known
to test anything — the most common way a security fix silently does nothing is
being "verified" by a test that would have passed either way. Three of the four
tests pass here, which proves the harness is real and the failure is specific.

The store enforces it: `findings.py fix` **refuses** to mark a finding fixed
without `--test`.

## Step 4 — The fix

```js
// before
const order = db.prepare('SELECT * FROM orders WHERE id = ?')
                .get(Number(orderMatch[1]));

// after
const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?')
                .get(Number(orderMatch[1]), me.id);
```

The ownership predicate goes in the `WHERE` clause, not in an `if` after the
fetch. A post-fetch check is one early return away from being bypassed, and it
loads the row into memory before anyone asks whether the caller may see it.
Scoping the query makes another user's order simply not exist.

It returns **404, not 403** — a 403 confirms the id is real and lets an
attacker enumerate order ids.

Live re-check after the fix:

```
Bob -> Alice's order: HTTP 404
Bob -> his own order: HTTP 200
```

Fixed, and legitimate access still works. Tests: 8/8.

## Step 5 — The part a Markdown report cannot do

Weeks later, a refactor drops the ownership scope. The next scan:

```
Run #3  (1 records from native)
  REGRESSED:  1  <-- previously fixed, now back

REGRESSED (was fixed, came back)  (1)
   [critical] idor4471  server.js:137  IDOR: GET /api/orders/:id ...

!! idor4471  critical regressed  T1 server.js:137
 + sqli0sea  critical fixed      T1 server.js:155
```

**Only the IDOR is flagged.** The SQL injection is still marked `fixed`,
because it never came back.

That precision is the point. A tool that re-ingested a static finding list
would flag both and be wrong about one — and a tool that cries wolf about
regressions gets ignored exactly like every other noisy scanner. The demo's
detector reads the current source, so the ledger reflects what is actually
there right now.

Full history, kept across sessions:

```
2026-08-16T01:14:19Z  discovered   detect.py (semantic check semgrep has no rule for)
2026-08-16T01:14:20Z  proven       tier 1: Bob(uid2) GET /orders/4471 -> 200 with Alice card_last4 4242
2026-08-16T01:14:21Z  fixed        test=test_order_idor.js
2026-08-16T01:14:24Z  regressed    was 'fixed', reappeared in found.json
```

A security fix that silently reverts is the most dangerous state a codebase can
reach, because everyone believes it is closed. This is the one failure mode a
Markdown report structurally cannot catch.

---

## What this demo does not prove

- **It is a fixture.** The vulnerabilities were planted, so "scanme found them"
  is weaker evidence than finding a bug in software nobody planted one in. What
  it does prove is that the *pipeline* works end to end, and that the regression
  detection is precise rather than trigger-happy.
- **Semgrep's 0 is not a criticism of Semgrep.** It is a correct result for a
  tool doing syntactic analysis on a semantic bug with an unfamiliar sink. The
  lesson is about what any static ruleset can see, not about one product.
- **Two vulnerabilities is not coverage.** vulnshop has no file uploads, no
  CSRF surface, no SSRF, no dependency tree. A clean run here says nothing about
  those classes.

## Files

| File | What it is |
|---|---|
| `server.js` | The vulnerable API. Both bugs are toggleable. |
| `test_order_idor.js` | IDOR regression test — verified red before the fix |
| `test_search_sqli.js` | SQLi regression test — verified red by reverting the fix |
| `detect.py` | Minimal source detector; reports what is actually present now |
| `toggle.py` | Flips each vulnerability on/off so the timeline is replayable |
| `run_demo.sh` | The whole loop in one command |

`run_demo.sh` restores the repo to the fixed state when it finishes.
