// vulnshop - a deliberately vulnerable API, in the shape real vibe-coded apps take.
//
// This is the fixture scanme's demo runs against. Every route below looks
// reasonable at a glance, which is the point: these are not contrived CTF
// puzzles, they are the mistakes that actually ship.
//
// Zero dependencies - node:sqlite and node:http are built in (Node 22.5+).
//   node server.js
//
// DO NOT DEPLOY THIS. It is vulnerable on purpose.

const http = require('node:http');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3771;
const SECRET = 'demo-signing-key-not-a-real-secret';

// ---------------------------------------------------------------- database

const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT,
    name TEXT
  );
  CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    item TEXT,
    total REAL,
    card_last4 TEXT
  );
  CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    price REAL
  );
`);

const hash = (pw) => crypto.createHash('sha256').update(pw).digest('hex');

db.prepare('INSERT INTO users VALUES (?,?,?,?)').run(1, 'alice@example.com', hash('alice123'), 'Alice Chen');
db.prepare('INSERT INTO users VALUES (?,?,?,?)').run(2, 'bob@example.com', hash('bob123'), 'Bob Martin');

db.prepare('INSERT INTO orders VALUES (?,?,?,?,?)').run(4471, 1, 'Noise-cancelling headphones', 349.99, '4242');
db.prepare('INSERT INTO orders VALUES (?,?,?,?,?)').run(4472, 1, 'Mechanical keyboard', 189.00, '4242');
db.prepare('INSERT INTO orders VALUES (?,?,?,?,?)').run(5013, 2, 'Standing desk', 620.50, '1881');

db.prepare('INSERT INTO products VALUES (?,?,?)').run(1, 'Noise-cancelling headphones', 349.99);
db.prepare('INSERT INTO products VALUES (?,?,?)').run(2, 'Mechanical keyboard', 189.00);
db.prepare('INSERT INTO products VALUES (?,?,?)').run(3, 'Standing desk', 620.50);

// ------------------------------------------------------------------ tokens

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}

function verify(token) {
  if (!token) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig !== expected) return null;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch {
    return null;
  }
}

function currentUser(req) {
  const auth = req.headers.authorization || '';
  return verify(auth.replace(/^Bearer\s+/i, ''));
}

// ------------------------------------------------------------------ routes

const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost:' + PORT);
  const path = url.pathname;

  // POST /api/login
  if (path === '/api/login' && req.method === 'POST') {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      let creds;
      try {
        creds = JSON.parse(raw);
      } catch {
        return send(res, 400, { error: 'Bad JSON' });
      }
      const user = db
        .prepare('SELECT * FROM users WHERE email = ? AND password_hash = ?')
        .get(creds.email, hash(creds.password || ''));
      if (!user) return send(res, 401, { error: 'Invalid credentials' });
      send(res, 200, { token: sign({ id: user.id, email: user.email }) });
    });
    return;
  }

  // GET /api/me
  if (path === '/api/me') {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Unauthorized' });
    const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(me.id);
    return send(res, 200, user);
  }

  // GET /api/orders/:id
  //
  // FIXED (was IDOR / broken object-level authorization).
  //
  // The ownership predicate lives in the WHERE clause rather than in an `if`
  // after the fetch. That is deliberate: a post-fetch check is one early
  // return away from being bypassed, and it means the row is loaded into
  // memory before anyone asks whether the caller was allowed to see it.
  // Scoping the query makes another user's order simply not exist.
  //
  // Guarded by test_order_idor.js, which failed before this change.
  const orderMatch = path.match(/^\/api\/orders\/(\d+)$/);
  if (orderMatch) {
    const me = currentUser(req);
    if (!me) return send(res, 401, { error: 'Unauthorized' });
    const order = db
      .prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?')
      .get(Number(orderMatch[1]), me.id);
    // 404, not 403 - a 403 would confirm the id exists and enable enumeration.
    if (!order) return send(res, 404, { error: 'Not found' });
    return send(res, 200, order);
  }

  // GET /api/search?q=
  //
  // FIXED (was SQL injection).
  //
  // The query text is now a constant and the input travels as a bound
  // parameter, so the driver never parses it as SQL. The wildcards belong in
  // the parameter value, not in the statement.
  //
  // Guarded by test_search_sqli.js, which failed before this change.
  if (path === '/api/search') {
    const q = url.searchParams.get('q') || '';
    try {
      const rows = db
        .prepare('SELECT id, name, price FROM products WHERE name LIKE ?')
        .all('%' + q + '%');
      return send(res, 200, { results: rows });
    } catch (err) {
      // Log the detail server-side; return something generic to the client.
      console.error('search failed:', err.message);
      return send(res, 500, { error: 'Search failed' });
    }
  }

  send(res, 404, { error: 'Not found' });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log('vulnshop listening on http://localhost:' + PORT);
    console.log('users: alice@example.com/alice123  bob@example.com/bob123');
  });
}

module.exports = { server, PORT };
