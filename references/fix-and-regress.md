# Phase 4 — Fixing, with the test written first

## The sequence, and why the order is load-bearing

1. Write the regression test that encodes the exploit.
2. **Run it against the vulnerable code. Confirm it fails.**
3. Apply the fix.
4. Run it again. Confirm it passes.
5. Run the full existing suite. Confirm nothing else broke.

Step 2 is the one that's tempting to skip and must not be. A test written after
a fix, never having been seen to fail, is untrustworthy — it may be asserting
something that was always true, testing the wrong endpoint, or silently
erroring in a way the runner counts as a pass. You'd then ship a fix "covered"
by a test that would never catch a regression. Watching it go red first is the
only thing that proves the test can detect the vulnerability at all.

If the test passes before you've fixed anything, don't shrug and move on. It
means either the test is wrong or the vulnerability isn't real — both are
important discoveries, and both change what you report.

## Writing the regression test

Put it where the project's tests live, matching their existing framework and
conventions. Name it for the vulnerability, not the function
(`test_cannot_read_another_users_order`, not `test_get_order_2`).

The test should assert the **security property**, not the implementation:

```js
// Good — survives refactors, states the actual rule
it('rejects reading an order belonging to another user', async () => {
  const res = await request(app)
    .get(`/api/orders/${userB.orderId}`)
    .set('Authorization', `Bearer ${userA.token}`);
  expect(res.status).toBe(403);
  expect(JSON.stringify(res.body)).not.toContain(userB.email);
});
```

Two assertions there, deliberately: the status code *and* the absence of
leaked data. Checking only the status misses a fix that returns 403 while still
including the data in the body — which sounds absurd until you've seen it.

For injection, assert the payload is handled as data:

```js
it('treats SQL metacharacters in search as literal text', async () => {
  const res = await request(app).get("/api/search?q=' OR '1'='1");
  expect(res.body.results).toHaveLength(0);  // not "everything"
});
```

## What to fix automatically

Fix when there is **one correct answer** and you can prove it with the test:

- **SQL injection** → parameterize. Mechanical, and the ORM/driver already
  supports it.
- **XSS via unescaped output** → use the framework's escaping, or sanitize with
  a library already in the project's dependencies. Don't hand-roll a sanitizer;
  hand-rolled ones are wrong.
- **Missing ownership check** → add the constraint to the query, *when the
  ownership model is unambiguous* (there's a clear `userId` on the resource and
  other handlers in the codebase already scope by it — match that pattern). If
  ownership is genuinely ambiguous — shared resources, team membership, nested
  permissions — that's a design question. Report it.
- **Missing auth on a route** → apply the project's existing auth middleware,
  when comparable routes clearly establish that this route should have it.
- **Mass assignment** → replace the spread with an explicit allowlist of fields.
- **Path traversal** → resolve the path and verify it's within the intended
  directory.
- **Insecure cookie flags** → add `httpOnly`, `Secure`, `SameSite`.
- **Dependency patches** that `npm audit fix` resolves without a major bump —
  then re-run the suite, and revert if anything breaks.

## What to report instead of fixing

Not because it's hard, but because a wrong guess here does real damage:

- **Cryptography.** Changing hashing, key derivation, token signing, or
  encryption affects existing stored data — a "fix" can lock every user out
  permanently or silently weaken security. Report with a specific
  recommendation and a migration note.
- **Authentication architecture.** Moving tokens from `localStorage` to
  httpOnly cookies, adding refresh rotation, changing session handling — these
  ripple through the whole app.
- **Authorization model changes** where ownership isn't already expressed in
  the data model. Inventing a permission model is a product decision.
- **Business logic.** You don't know whether coupons are *supposed* to stack.
- **Anything requiring infrastructure or credentials** — WAF rules, secret
  rotation, cloud IAM, security headers at the CDN.
- **Secrets already committed to git history.** Deleting the file doesn't
  remove it from history, and rotation is the real fix. Say so; don't paper
  over it.
- **Anything you couldn't write a passing test for.** No test, no fix. Report it
  with the suggested patch and say explicitly that it's unverified.

## Fix hygiene

- **One fix per finding**, kept minimal. A security fix bundled with a refactor
  is hard to review and hard to revert — and it will be reviewed.
- **Don't break the API contract.** Returning 403 where the app returned 200 is
  the point; changing a response shape is not.
- **Prefer the project's existing patterns.** If other handlers use a
  `requireOwnership()` helper, use it rather than inlining a novel check.
- **Re-run the full suite after every fix**, not once at the end. When
  something breaks you want to know which change did it.
- **If a fix breaks existing tests**, stop and think rather than editing the
  test to pass. Sometimes the existing test was asserting the vulnerable
  behavior (genuinely fine to update — note it in the report). Sometimes your
  fix is wrong. Never adjust a test just to get green.

## If there's no test framework

Say so, and don't fabricate infrastructure. Options, in order of preference:

1. Ask the user whether to add a minimal test setup — often welcome, but it's
   their call, since it adds a dependency.
2. Provide a standalone reproduction script (`curl` or a small file) that
   demonstrates the vulnerability, and have the user confirm the behavior
   changes after the fix.
3. Report the finding with a patch and state clearly that it wasn't applied
   because it couldn't be verified.

Option 3 is a perfectly good outcome. The promise of this skill is that
everything it *claims* is proven — not that it fixes everything regardless.
