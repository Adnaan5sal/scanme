// Regression test for the IDOR in GET /api/orders/:id
//
// Written BEFORE the fix, and confirmed failing against the vulnerable code.
// That order matters: a security test that has never gone red is not known to
// test anything. If this had passed on the unfixed server, it would be broken
// and the "fix" it guards would be unverified.
//
//   node --test test_order_idor.js
//
// Zero dependencies - node:test and node:assert are built in.

const test = require('node:test');
const assert = require('node:assert');
const { server } = require('./server.js');

let base;

test.before(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  base = 'http://localhost:' + server.address().port;
});

test.after(() => server.close());

async function login(email, password) {
  const res = await fetch(base + '/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  assert.strictEqual(res.status, 200, 'login should succeed for ' + email);
  return (await res.json()).token;
}

// Two distinct non-admin users is the non-negotiable part of this fixture.
// With a single user you can only test logged-in vs. anonymous, which misses
// the entire user-to-user authorization bug class - exactly the bug here.
const ALICE_ORDER = 4471;
const BOB_ORDER = 5013;

test('the owner can read their own order', async () => {
  const alice = await login('alice@example.com', 'alice123');
  const res = await fetch(base + '/api/orders/' + ALICE_ORDER, {
    headers: { Authorization: 'Bearer ' + alice },
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.id, ALICE_ORDER);
});

test('anonymous requests are rejected', async () => {
  const res = await fetch(base + '/api/orders/' + ALICE_ORDER);
  assert.strictEqual(res.status, 401, 'unauthenticated access must be denied');
});

test("a user CANNOT read another user's order", async () => {
  const bob = await login('bob@example.com', 'bob123');
  const res = await fetch(base + '/api/orders/' + ALICE_ORDER, {
    headers: { Authorization: 'Bearer ' + bob },
  });

  // 404 rather than 403: confirming the id exists is itself a leak, and lets
  // an attacker enumerate valid order ids.
  assert.strictEqual(
    res.status,
    404,
    "Bob received HTTP " + res.status + " for Alice's order - expected 404"
  );

  // Asserting on the status alone is not enough. A handler can set an error
  // status while still having serialized the record into the body, so check
  // the data itself never crossed the boundary.
  const text = await res.text();
  assert.ok(!text.includes('4242'), "response leaked Alice's card_last4");
  assert.ok(!text.includes('Noise-cancelling'), "response leaked Alice's order contents");
});

test('legitimate access still works after the fix', async () => {
  const bob = await login('bob@example.com', 'bob123');
  const res = await fetch(base + '/api/orders/' + BOB_ORDER, {
    headers: { Authorization: 'Bearer ' + bob },
  });
  assert.strictEqual(res.status, 200, 'the fix must not break legitimate access');
  const body = await res.json();
  assert.strictEqual(body.id, BOB_ORDER);
});
