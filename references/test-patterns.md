# Standing test suite patterns — widening coverage beyond one fix

Phase 4 of Audit Mode writes one regression test per proven finding. This
reference is for the bigger ask: "write me security tests" / "how do I stop
this class of bug coming back" / turning an audit into permanent CI coverage
rather than one-off fixes.

**The most valuable output by a wide margin is the authorization matrix** —
broken access control is both the most common serious web vulnerability and
the one most likely to be reintroduced by ordinary feature work, since a new
endpoint that copies an existing handler can silently drop the ownership
filter.

Examples below are Jest/supertest and pytest; translate to the project's
actual framework rather than introducing a new test stack.

## Fixtures — build these once

```js
// tests/security/fixtures.js
export async function setup() {
  const userA = await createUser({ email: 'a@test.local' });
  const userB = await createUser({ email: 'b@test.local' });
  const admin = await createUser({ email: 'admin@test.local', role: 'admin' });

  // Each non-admin user owns a resource, so cross-access can be tested
  const orderA = await createOrder({ userId: userA.id });
  const orderB = await createOrder({ userId: userB.id });

  return { userA, userB, admin, orderA, orderB, anon: null };
}
```

Two regular users is the non-negotiable part. With one user you can only test
"logged in vs. not," which misses the entire class of user-to-user
authorization bugs — the same class the flagship demo in this skill proves.

## 1. Authorization matrix

Express the rules as data, then drive the tests from it:

```js
// [method, path, actor, expectedStatus]
const matrix = [
  ['GET',    '/api/orders/:ownOrder',    'userA', 200],
  ['GET',    '/api/orders/:otherOrder',  'userA', 404],  // not 403 — see note
  ['GET',    '/api/orders/:otherOrder',  'anon',  401],
  ['DELETE', '/api/orders/:otherOrder',  'userA', 404],
  ['GET',    '/api/admin/users',         'userA', 403],
  ['GET',    '/api/admin/users',         'admin', 200],
];

describe('authorization matrix', () => {
  test.each(matrix)('%s %s as %s -> %i',
    async (method, path, actor, expected) => {
      const res = await request(app)[method.toLowerCase()](resolve(path))
        .set(authHeader(actor));
      expect(res.status).toBe(expected);
    });
});
```

**Assert on absence of data, not just status.** A handler can return 403
while still including the resource in the body:

```js
test('userA cannot read userB order contents', async () => {
  const res = await request(app)
    .get(`/api/orders/${orderB.id}`)
    .set(authHeader('userA'));
  expect(res.status).toBe(404);
  expect(JSON.stringify(res.body)).not.toContain(userB.email);
});
```

**On 404 vs 403:** returning 404 for someone else's resource avoids
confirming the ID exists, which blocks enumeration. Either is defensible —
the test should assert whichever the app actually intends, consistently.

## 2. Authentication

```js
describe('protected route rejects bad credentials', () => {
  const cases = [
    ['no token',       {}],
    ['malformed token',{ Authorization: 'Bearer not-a-token' }],
    ['expired token',  { Authorization: `Bearer ${expiredToken}` }],
    ['unsigned token', { Authorization: `Bearer ${algNoneToken}` }],
  ];
  test.each(cases)('%s', async (_label, headers) => {
    const res = await request(app).get('/api/me').set(headers);
    expect(res.status).toBe(401);
  });
});
```

The `alg: none` case catches a JWT library configured to accept unsigned
tokens — a total auth bypass that produces perfectly normal-looking code.

## 3. Input handling

Assert on **behavior**, not on error text. Error strings change; behavior
shouldn't.

```js
test('SQL metacharacters are treated as literal search text', async () => {
  const res = await request(app).get("/api/search?q=' OR '1'='1");
  expect(res.status).toBe(200);
  expect(res.body.results).toHaveLength(0);   // not "every row"
});

test('stored HTML is escaped when rendered', async () => {
  await request(app).post('/api/comments')
    .set(authHeader('userA'))
    .send({ body: '<img src=x onerror=alert(1)>' });
  const page = await request(app).get('/comments');
  expect(page.text).not.toContain('<img src=x onerror=');
  expect(page.text).toContain('&lt;img');
});

test('NoSQL operators in login body do not bypass auth', async () => {
  const res = await request(app).post('/api/login')
    .send({ email: 'a@test.local', password: { $ne: null } });
  expect(res.status).toBe(400);   // or 401 — never 200
});
```

## 4. Rate limiting

```js
test('login is rate limited', async () => {
  const attempts = [];
  for (let i = 0; i < 20; i++) {
    attempts.push(await request(app).post('/api/login')
      .send({ email: 'a@test.local', password: 'wrong' }));
  }
  expect(attempts.some(r => r.status === 429)).toBe(true);
});
```

Reset the limiter between tests, or this makes unrelated tests flaky — which
typically ends with someone deleting the rate-limit test rather than fixing
the isolation.

## 5. Sessions

```js
test('logout invalidates the session', async () => {
  const token = await login(userA);
  await request(app).post('/api/logout').set({ Authorization: `Bearer ${token}` });
  const after = await request(app).get('/api/me').set({ Authorization: `Bearer ${token}` });
  expect(after.status).toBe(401);
});

test('password change invalidates other sessions', async () => {
  const oldToken = await login(userA);
  await changePassword(userA, 'new-password');
  const res = await request(app).get('/api/me')
    .set({ Authorization: `Bearer ${oldToken}` });
  expect(res.status).toBe(401);
});

test('session cookie has security flags', async () => {
  const res = await request(app).post('/api/login').send(validCreds);
  const cookie = res.headers['set-cookie'][0];
  expect(cookie).toMatch(/HttpOnly/i);
  expect(cookie).toMatch(/Secure/i);
  expect(cookie).toMatch(/SameSite/i);
});
```

## 6. Coverage self-check — makes gaps self-reporting

A test that enumerates the app's actual routes and fails if any route has no
matrix entry. Without it, the suite silently stops covering new endpoints the
moment someone adds one — exactly when coverage matters most.

```js
test('every route is covered by the authorization matrix', () => {
  const registered = listRoutes(app);                    // framework-specific
  const covered = new Set(matrix.map(([m, p]) => `${m} ${p}`));
  const missing = registered.filter(r => !covered.has(r));
  expect(missing).toEqual([]);
});
```

## Python / pytest equivalent

```python
@pytest.mark.parametrize("method,path,actor,expected", MATRIX)
def test_authorization_matrix(client, fixtures, method, path, actor, expected):
    resp = client.open(resolve(path, fixtures),
                       method=method,
                       headers=auth_header(actor, fixtures))
    assert resp.status_code == expected
```

## Verify the tests actually test something

**A test that has never failed is not yet known to work** — the same
discipline as Phase 4's fix-with-test-first rule. For at least the
authorization tests, confirm each one detects the thing it claims to:
temporarily remove the ownership filter, run the test, confirm it fails,
restore the filter, confirm it passes. In the working tree only — never
commit the broken state.

## Scope and honesty

- **Passing tests prove the specific properties tested, nothing more.** They
  don't prove the app is secure. Coverage is exactly the endpoints and cases
  enumerated.
- **New endpoints aren't automatically covered.** Mention that adding an
  endpoint means adding rows, and add the coverage self-check.
- These tests complement Audit Mode; they don't replace it. Tests check the
  rules you thought to write down. A proof-based audit looks for the ones
  you didn't.

## Wiring into CI

Add the suite to the existing test command so it runs on every push. Keep
security tests in their own directory (`tests/security/`) so they can be run
and reported separately — a failing authorization test deserves more
attention than a flaky snapshot test.
