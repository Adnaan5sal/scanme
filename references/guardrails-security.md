# Security guardrails — apply while writing the code

These are written as **what to do while writing the code**, not what to
detect afterward. Apply the relevant section the moment you're writing that
kind of code. (For the "how would an attacker actually exploit this if it's
already there" version of the same classes, see
[vulnerability-classes.md](vulnerability-classes.md).)

## Authentication

- Use an established auth library or provider (NextAuth/Auth.js, Passport,
  Supabase Auth, Clerk, Firebase Auth) rather than hand-rolling session
  logic. Hand-rolled auth is where subtle, serious bugs live.
- Hash passwords with **bcrypt, scrypt, or argon2id** — never MD5, SHA1, or
  plaintext. If the library/framework has a built-in hasher, use it rather
  than importing a new dependency.
- Password-reset and email-verification tokens: generate with a
  cryptographically secure random source (`crypto.randomBytes`, not
  `Math.random()`), make them single-use, and expire them (an hour is a
  reasonable default absent other guidance).
- Don't let a login/reset endpoint reveal whether an account exists —
  respond the same way for "wrong password" and "no such user."
- When wiring OAuth (Google/GitHub/etc.): validate the `state` parameter,
  use PKCE if the library supports it, and don't trust identity claims from
  the provider without validating the token signature.

## Authorization — the one that matters most

Authentication tells you who someone is. It says nothing about what they may
touch. This is the single most common gap in fast-built apps, because
*forgetting* the check produces code that looks completely normal and runs
without error.

**The rule to apply every time you write a handler that fetches or mutates a
specific resource by ID:** the query must be scoped to the current user (or
their permitted scope), not just filtered by the resource's own ID.

```js
// Don't write this — authenticated, but not authorized
const order = await Order.findById(req.params.id);

// Write this instead — ownership is part of the query itself
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
if (!order) return res.status(404).json({ error: 'Not found' });
```

This applies to every resource type with an owner: orders, documents,
messages, uploaded files, settings, API keys. Ask yourself, for every
`GET`/`PUT`/`PATCH`/`DELETE` that takes an ID: *if a different logged-in user
guessed or incremented this ID, would they get someone else's data?* If yes,
add the scoping before moving on.

- Never trust a role or permission claim from the client (a hidden field, a
  request body `role: "admin"`) — check permissions server-side against
  data the server controls.
- When updating a model from request data, use an explicit allowlist of
  fields rather than spreading the whole body — `Object.assign(user,
  req.body)` lets an attacker set `role` or `isVerified` if those fields
  happen to exist on the model.
- Admin/privileged routes get the same ownership discipline, plus an
  explicit role check applied as middleware, not scattered per-handler.

## Injection

- **SQL**: use parameterized queries or your ORM's query builder. Never
  build a query by concatenating or template-interpolating request data into
  SQL text. If you must use a raw/unsafe query method for something the
  builder can't express, isolate that call and comment why.
- **NoSQL**: don't pass a request body directly into a Mongo-style filter —
  `db.users.find(req.body)` lets `{"password": {"$ne": null}}` through as a
  query operator. Pick specific fields out of the body instead.
- **Command execution**: avoid `exec`/`spawn` with any request-derived
  string. If shelling out is unavoidable, pass arguments as an array (not a
  single interpolated string) so the shell can't reinterpret them.
- **Path handling**: when a filename or path comes from the request, resolve
  it and verify the result stays inside the intended directory before using
  it — don't just concatenate.

## Cross-site scripting (XSS)

- In React/Vue/Angular, rely on the framework's default escaping. The only
  way to introduce XSS is through the explicit escape hatches
  (`dangerouslySetInnerHTML`, `v-html`, raw `innerHTML`) — avoid them for
  anything that includes user or API-sourced content. If you must render
  HTML the user supplied, run it through a sanitizer library first
  (DOMPurify or equivalent), not a hand-written stripper.
- Watch `href`/`src` attributes built from user input — a `javascript:` URL
  executes even though no HTML was injected. Validate the scheme.
- Server-rendered templates: confirm the templating engine auto-escapes by
  default (most do); if you're building raw HTML strings, escape manually.

## Secrets

- Never hardcode an API key, token, or connection string in source, even
  temporarily "to test" — it's easy to forget and commit.
- Env vars exposed to the client carry a framework-specific prefix
  (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`). Before naming a new env var,
  decide explicitly whether it's client-safe. A server-only secret with a
  client-exposed prefix ships to every visitor's browser — this is the
  single most common secrets mistake in fast-built apps, particularly with
  Supabase `service_role` keys.
- When creating `.env`/`.env.local`, confirm `.gitignore` already excludes
  it before the first commit touches the project — check, don't assume.

## CORS

- Don't reach for `origin: '*'` on any route that reads authentication state
  (cookies, bearer tokens) — pair a specific allowed origin (or an explicit
  allowlist) with credentialed requests instead.
- If you're reflecting the request's `Origin` header back as the allowed
  origin, validate it against an allowlist first — reflecting it
  unconditionally is equivalent to a wildcard for authenticated requests.

## SSRF

- Any server-side code that fetches a URL supplied (directly or indirectly)
  by the user — link previews, webhook registration, "import from URL",
  image-by-URL — needs the target validated before the request goes out.
  Block loopback and link-local ranges (`127.0.0.1`, `169.254.169.254`,
  private RFC1918 ranges) at minimum; cloud metadata endpoints are the
  highest-value SSRF target and are exactly the address that naive
  allowlisting misses.

## File uploads

- Validate file type by content (magic bytes / a library that inspects the
  actual file), not just the extension or the client-supplied MIME type —
  both are attacker-controlled.
- Enforce a size limit before the file is fully read into memory.
- Store uploads outside any directory served as static/executable, and
  generate the stored filename yourself rather than trusting the uploaded
  name (which can carry `../` or other traversal payloads).
- Don't allow uploaded files to be executed or interpreted — serve them with
  a `Content-Disposition` that forces download for anything not meant to be
  rendered inline.

## Cookies and sessions

- Set `httpOnly`, `Secure`, and an explicit `SameSite` on any
  session/auth cookie.
- Choose a session lifetime deliberately rather than leaving a default —
  and invalidate/rotate the session on password change or logout.
