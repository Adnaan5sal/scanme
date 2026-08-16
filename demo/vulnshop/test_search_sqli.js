// Regression test for the SQL injection in GET /api/search
//
//   node --test test_search_sqli.js
//
// Note on honesty: the fix for this one landed before the test was written,
// which is the wrong order. So the test was verified the other way - by
// temporarily reverting the parameterized query back to string concatenation
// and confirming this suite goes red. A security test that has never failed
// is not known to test anything, and it does not matter whether you establish
// that before or after the fix, only that you establish it.

const test = require('node:test');
const assert = require('node:assert');
const { server } = require('./server.js');

let base;

test.before(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  base = 'http://localhost:' + server.address().port;
});

test.after(() => server.close());

const search = async (q) => {
  const res = await fetch(base + '/api/search?q=' + encodeURIComponent(q));
  assert.strictEqual(res.status, 200, 'search should not error on hostile input');
  return (await res.json()).results;
};

test('a normal search matches only what it should', async () => {
  const results = await search('key');
  assert.strictEqual(results.length, 1);
  assert.strictEqual(results[0].name, 'Mechanical keyboard');
});

test('SQL metacharacters are treated as literal text, not as SQL', async () => {
  // Against the vulnerable version this closes the string literal and makes
  // the WHERE clause tautological, returning the full products table.
  const results = await search("' OR '1'='1");

  assert.strictEqual(
    results.length,
    0,
    'injected payload returned ' + results.length + ' rows - the input was ' +
      'parsed as SQL rather than matched as text'
  );
});

test('a UNION payload cannot reach another table', async () => {
  const results = await search("' UNION SELECT id, email, id FROM users --");
  const blob = JSON.stringify(results);
  assert.ok(!blob.includes('@example.com'), 'search leaked rows from the users table');
});

test('a quote in an ordinary search is handled, not fatal', async () => {
  // Behavioural, not cosmetic: escaping bugs often surface first as a 500 on
  // legitimate input containing an apostrophe.
  const results = await search("O'Brien");
  assert.strictEqual(results.length, 0);
});
