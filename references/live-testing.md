# Live target testing — safe dynamic methodology

Strix's differentiator over a static reviewer is testing a *running* target:
HTTP interception and browser automation, not just source. This is the
methodology for doing that safely, whether the target is `owner` scope (your
own local/staging instance) or `third-party` scope (an authorized
engagement).

**Gate first, always.** Before anything in this file runs against a target
that isn't `http://localhost`/`127.0.0.1`, check authorization:

```bash
python scripts/authorize.py check --target <url>
```

If it fails, stop. Record authorization first (see the workflow in
`SKILL.md` — owner vs third-party distinction) — this is not a formality, it
gates every subsequent phase.

## HTTP-level testing

Safe payloads only, same discipline as every other proof in this skill
family — the goal is to demonstrate a vulnerability exists, not to cause
damage:

- SQL injection: `SLEEP(5)` / time-based blind, never `DROP`/`DELETE`/`UPDATE`
- Command injection: a marker file to a scratch path (`touch
  /tmp/swarm-poc-<random>`), never a destructive command
- Path traversal: read a known-benign file (`/etc/hostname`,
  `C:\Windows\win.ini`), never write outside the intended directory
- Auth bypass: use test accounts the user provides, never attempt to guess
  or brute-force real credentials
- Rate limiting: a bounded burst (20-30 requests), not a sustained flood —
  this is a functional test, not a DoS

Run exploit scripts through `scripts/sandbox_exec.sh` rather than directly —
see that file's own docs for what containment it actually provides.

Respect scope: for `third-party` authorization, the recorded `--note` may
specify a narrower scope (e.g. `*.acme.com` only) — never test outside what
was actually authorized, even if a broader target seems reachable from
where you are.

## Browser-based testing (the client-side agent's job)

Uses the `mcp__Claude_Browser__*` tools already available in this
environment — this is the part scanme's static Audit Mode structurally
cannot do, because XSS execution, CSRF, and clickjacking are runtime
behaviors that don't exist in source code alone.

**Reflected/DOM XSS** — navigate to a URL with a test payload
(`<script>window.__swarm_xss=true</script>` — inert, self-identifying, not
`alert()` which produces an intrusive dialog), then check
`javascript_tool` for whether `window.__swarm_xss` is set. A benign,
self-checking payload is Tier 1 proof without side effects.

**Stored XSS** — submit the payload through the app's normal flow (a
comment, a profile field), then navigate to wherever it's rendered and
check the same way.

**CSRF** — use `read_network_requests` to inspect whether state-changing
requests include a CSRF token or rely solely on cookies with a weak
`SameSite` policy; confirm by checking response headers, not by actually
executing a cross-origin attack against the user's own session.

**Secrets/over-exposure in responses** — `read_network_requests` on API
responses the frontend never renders (browser dev-tools-style inspection);
look for fields present in the JSON but never displayed — a common way
`SELECT *` leaks internal fields nobody meant to expose.

**Console/error leakage** — `read_console_messages` for stack traces,
debug logs, or verbose errors exposed to the client.

## What still requires Docker (honestly out of scope without it)

Full HTTP interception (a real proxy sitting between client and server,
rewriting requests live — what Caido/Burp do) is not replicated here. The
`fetch`/`curl`-based HTTP testing above covers direct request crafting,
which is the majority of what's needed for injection/auth testing, but not
live traffic modification of an app's own outgoing requests. Say this
plainly if the user needs true interception — recommend Burp Suite or
Caido directly rather than pretending this covers it.
