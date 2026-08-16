# Verification — turning candidates into proof

This is the core of the audit. Everything else is preparation for this step.

## Why this is worth the effort

A candidate is a hypothesis: "attacker-controlled data reaches a dangerous
operation without adequate defense." Hypotheses are frequently wrong in ways
that aren't visible from the line of code that raised the flag — the input
turns out to be a validated enum, a framework escapes by default, middleware
three files away sanitizes everything, the route is unreachable in production
builds.

Reporting a hypothesis as a finding is the single behavior that makes security
tooling untrustworthy. So: prove it, or say you couldn't.

## Tier 1 — Executable reproduction

The strongest evidence. You cause the vulnerability to happen and observe the
result.

**Setup.** Get the app running locally (`npm run dev`, `docker compose up`,
whatever the project uses). If it needs a database, use the project's own
seed/migration tooling. Create at least **two distinct test users** — an
enormous fraction of real-world vulnerabilities are authorization bugs, and you
cannot demonstrate "user A reads user B's data" with only one account.

**Execution.** Drive the vulnerability the way an attacker would:
- Authorization (IDOR): authenticate as user A, request a resource belonging to
  user B, observe B's data in the response.
- Injection: send a payload that produces an observable, unambiguous effect —
  `' OR '1'='1` returning more rows than the query should, a time-delay
  payload measurably delaying the response, a command payload writing a marker
  file to `/tmp`.
- XSS: submit a payload, then verify it appears **unescaped in the rendered
  output** — check the actual HTML response body or DOM, not just that the
  string was stored. Stored-but-escaped is not XSS.
- Auth bypass: request a protected route with no session, an expired token, or
  a token belonging to a lower-privileged role, and observe success.

**Use safe payloads.** The goal is proof, not damage. A `SLEEP(5)` or a
`SELECT 1` proves injection as conclusively as `DROP TABLE` and destroys
nothing. Write marker files to temp directories, never overwrite anything. Read
data belonging to your own test users, never real user data. If a proof would
require actually destroying or exfiltrating something, stop — describe the
mechanism and downgrade to Tier 2 rather than doing damage to prove a point.

**Record.** Exact request (method, path, headers, body), exact response
excerpt showing the vulnerability, and what specifically about that response
constitutes proof. "Returned 200" is not proof. "Returned user B's email
address `userb@test.local` while authenticated as user A" is.

## Tier 2 — Traced data flow

Use when the app can't be run — no runnable environment, missing credentials,
external dependencies unavailable. This is rigorous static proof, and it's only
valid if the trace is *complete*.

You must be able to state all three of these with quoted code:

1. **Source** — the exact expression where attacker-controlled data enters.
   `req.query.id` at `routes/orders.js:14`. Quote the line.
2. **Path** — every hop from source to sink. Each assignment, function call,
   parameter pass. Quote each one. If the value passes through a function you
   haven't read, read it — that function is where the sanitizer usually lives.
3. **Sink** — the dangerous operation, quoted, showing the tainted value
   arriving unsanitized.

Then the part people skip: **actively look for the defense that would
invalidate your trace.** Check for framework-level auto-escaping, global
middleware, ORM parameterization, validation decorators, a WAF config, a type
system that constrains the value. Go looking for the reason you're wrong. If
you find one, the candidate is discarded — and that's a good outcome.

If any hop is "I assume this passes through unchanged" — that's a gap, and a
trace with a gap is Tier 3, not Tier 2. Be strict with yourself here; this is
exactly where motivated reasoning creeps in.

## Tier 3 — Unproven leads

Everything that didn't reach Tier 1 or Tier 2. These are **not vulnerabilities**
and must never be written up as if they were.

Each lead gets: the location, what made it suspicious, and — most importantly —
**the specific thing that blocked confirmation**. "Could not verify whether
`sanitizeInput()` at `utils/clean.js:8` handles the `javascript:` scheme" tells
the developer exactly where to look and is genuinely useful. "Potential XSS
risk" is noise.

Also record **discarded** candidates and why. A one-line note that
`renderTemplate()` output is auto-escaped by the engine saves the next auditor
(human or model) from re-raising it.

## Guarding against your own bias

You will want to find things. Vigilance against that:

- **Try to disprove each candidate before trying to prove it.** Ask "what would
  make this safe?" and go look for it. If you can't find any defense after
  genuinely searching, the finding is much stronger.
- **Distrust the pattern, trust the trace.** `innerHTML` is not a vulnerability.
  `innerHTML` fed by `location.hash` with no sanitizer is.
- **Check reachability in production.** A vulnerable route behind a
  `NODE_ENV === 'development'` guard, or dead code no router references, is not
  exploitable. Verify the code actually runs in a production build.
- **One proof per finding.** Don't bundle "and probably these other five places
  too" into one entry. Each location needs its own proof or its own lead entry.

## When you're done

State your coverage honestly: which entry points you tested, which you
couldn't, and why. A reader who knows you tested 12 of 15 routes and which 3
you skipped is far better served than one given a confident-sounding report
with unstated gaps.
