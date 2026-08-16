# Phase 1 — Mapping the attack surface

Goal: before hunting anything, know where untrusted data enters, where it can
do damage, and who is allowed to do what. Vulnerabilities live at the seams
between those, and you can't see seams you haven't mapped.

Budget real time here. An audit that skips this finds only what regex finds.

## Step 1 — Understand the app

- What does it do, and what's the most valuable thing an attacker could take?
  (User data? Money movement? Admin access? Compute?) This sets your priorities
  for everything after.
- Stack, framework, and framework version — defaults matter enormously. React
  escapes by default; a raw template string doesn't. An ORM parameterizes;
  hand-built SQL doesn't. Know what you're getting for free before hunting for
  its absence.
- Deployment shape: single server, serverless, containerized, static + API,
  BaaS (Supabase/Firebase — these push authorization into row-level policies,
  which is a distinct and commonly-broken surface).

## Step 2 — Inventory entry points

Every place attacker-controlled data enters. Be exhaustive; the forgotten one
is where the bug is.

- **HTTP routes** — enumerate them all from the router/framework conventions
  (`app.get(...)`, file-based routing directories, controller annotations). For
  each: method, path, params, and whether it requires auth.
- **Request components beyond the body** — query strings, path params, headers
  (including `Host`, `X-Forwarded-*`, `Referer`), cookies, and content-type.
  Header-sourced injection is routinely missed because people only look at the
  body.
- **Forms and client-side handlers**, including anything reading
  `location.hash`, `location.search`, `postMessage`, or `localStorage` and
  passing it onward.
- **File uploads** — filename, content, content-type, and size are all
  attacker-controlled.
- **Webhooks and third-party callbacks** — payment providers, OAuth callbacks,
  CI hooks. These are attacker-reachable URLs, and signature verification is
  very often missing.
- **Websockets / realtime channels** — message payloads, plus the subscription
  authorization model.
- **Anything reading from a queue, cron-triggered job, or scheduled task** that
  processes user-supplied data.

## Step 3 — Locate the sinks

Dangerous operations that misbehave when given hostile input:

| Sink type | What to grep for |
|---|---|
| SQL | raw `query(`, `execute(`, template literals containing `SELECT`/`INSERT`/`UPDATE`/`DELETE`, `.raw(` |
| Command | `exec`, `execSync`, `spawn`, `child_process`, `os.system`, `subprocess`, backticks |
| HTML render | `dangerouslySetInnerHTML`, `v-html`, `.innerHTML`, `document.write`, `\|safe`, `{{{ }}}` |
| Filesystem | `readFile`, `createReadStream`, `sendFile`, `path.join` with request data |
| Redirect | `res.redirect`, `location.href =`, `window.open` with request data |
| Deserialization | `JSON.parse` of signed data, `pickle`, `yaml.load`, `eval`, `Function(` |
| Outbound request | `fetch`/`axios`/`requests` with a URL derived from input (SSRF) |
| Auth decision | session lookups, token verification, role/permission comparisons |

Record file:line for each. This list crossed with your entry-point list is your
candidate space.

## Step 4 — Map the authorization model

This deserves its own step because broken access control is consistently the
most common serious vulnerability in fast-built apps, and it's invisible to
pattern matching — the code looks completely normal.

Answer these explicitly:

- How does a request become authenticated? Where is the session/token verified,
  and is that check applied globally (middleware) or per-route (easy to forget
  on one route)?
- What roles/permission levels exist?
- **For each resource type: how does the app decide that this user may access
  this specific object?** Write this down per resource. The classic bug is a
  handler that looks up `Order.findById(req.params.id)` and returns it —
  authentication present, ownership check absent.
- Is authorization enforced server-side, or does the client just hide the
  button? Check whether the API endpoint itself refuses the request.
- For BaaS/Supabase: are row-level security policies enabled on every table
  that's client-writable? A table with RLS off is world-readable through the
  public anon key.

## Step 5 — Note the defenses that already exist

Just as important as finding gaps — this is what prevents false positives later.

- Global middleware: helmet, CSRF protection, rate limiters, body validation,
  auth guards. Note the order they run in and which routes they cover; a guard
  registered after a route doesn't protect it.
- Validation libraries in use (zod, joi, pydantic, class-validator) and which
  endpoints actually use them versus just import them.
- Framework auto-escaping behavior.
- Content Security Policy — presence, and whether it's meaningfully restrictive
  or just `unsafe-inline` everywhere.

## Output

Produce a written surface map before moving to Phase 2:

```
Entry points:      <count> routes (<n> authenticated, <n> public), <n> webhooks,
                   <n> upload handlers
Sinks:             <list by type with file:line>
Auth model:        <how authN works, what roles exist, how ownership is checked>
Existing defenses: <middleware, validation, escaping, CSP>
Highest-value targets: <what an attacker would actually want here>
```

This becomes the "Scope" section of the final report, which is how the reader
knows what you examined — and, just as importantly, what you didn't.
