# Production readiness — beyond security

Everything in this file is non-security production risk: error handling,
code quality, performance, deploy configuration, and accessibility. Security
findings (injection, auth, secrets, etc.) go through
[vulnerability-classes.md](vulnerability-classes.md) instead — don't
duplicate that ground here, and don't let a readiness pass re-derive findings
Audit Mode already owns.

Apps built fast with AI assistance tend to accumulate a predictable set of
gaps: no error handling around I/O, debug `console.log`s left in, no
`.env.example`, hardcoded `localhost` URLs, no loading/error states,
vulnerable dependencies. None of these are exotic — they're the boring stuff
that "wasn't the point" while the feature was being built.

Read the code and understand what it does; don't just pattern-match on
keywords. `scripts/scan_common_issues.sh <project-root>` gives a fast
grep-based first pass (debug artifacts, TODO markers, hardcoded localhost,
possible secrets, swallowed errors, XSS sinks, wildcard CORS, `.env` hygiene)
— treat every hit as a lead to verify, not a finding, same discipline as
Phase 2 of Audit Mode.

## Error handling

- Every I/O boundary (network fetch, DB query, file read/write, external API
  call) should have a failure path. Look for `await` calls with no
  surrounding try/catch and no caller-level catch either, `.then()` chains
  with no `.catch()`, and fire-and-forget promises where a failure would
  vanish silently.
- **Silent failure** — `catch (e) {}` or `catch (e) { console.log(e) }` with
  no actual recovery or surfacing to the user. A very common vibe-coding
  artifact (added to stop a crash during dev, never revisited). Fixable when
  there's an established pattern elsewhere in the codebase to match; flag if
  there's no established pattern, since inventing one is a design decision.
- Frontend: missing error boundaries around route-level components, or
  missing error states in data-fetching hooks (no "something went wrong" UI,
  just a blank screen or crash on failed fetch).
- Backend: confirm unhandled errors in request handlers don't crash the
  process or leak stack traces / internal details to the client response.

## Code quality

- Dead code: unused exports, unreachable branches, commented-out old
  implementations. Safe to remove when the linter/type-checker can confirm
  "unused"; leave ambiguous cases (might be intentionally kept for
  reference, or feature-flagged) alone and flag instead.
- Debug artifacts: `console.log`/`print`/`debugger` statements, commented-out
  `alert()`s, temporary hardcoded test values in place of real logic
  (`const userId = 1 // TODO: get from auth`). Safe and expected to fix —
  but read each one: a `console.error` inside an actual error handler is
  often intentional logging, not debug residue.
- `TODO`/`FIXME`/`HACK` markers: don't resolve the underlying issue yourself
  (usually a judgment call), but surface them grouped by what they're
  flagging.
- Unused dependencies: flag rather than remove — a dependency can be used in
  ways static analysis misses (dynamic imports, config references, peer
  dependency requirements).

## Performance

### Database and data access

- N+1 queries: a loop (or `.map`/`Promise.all` over a list) issuing one
  query per item where a single batched query would do. Flag rather than
  auto-fix when the rewrite changes query structure — note the specific loop
  and the batched alternative.
- Missing indexes: compare which columns queries filter/sort/join on against
  the schema. Flag with the specific suggested index — adding an index is a
  migration, the user's call.
- Unbounded queries: `SELECT *` with no limit on a growing table, list
  endpoints with no pagination. Flag; pagination changes the API contract.
- Connection handling: connections opened per-request without pooling, or
  opened and never closed.

### Frontend performance

- Images: unoptimized formats/sizes, missing `width`/`height` (layout
  shift), not using the framework's image component. Adding explicit
  dimensions is usually safe to auto-fix; swapping to a framework image
  component can change layout, so flag it.
- Bundle size: large dependencies imported wholesale where a submodule
  import would do, dev-only libraries in production dependencies, no code
  splitting on a large multi-route app.
- Render performance: expensive computation in a render path with no
  memoization, or an effect with a missing/incorrect dependency array
  causing refetch loops — fix if the correct deps are unambiguous.
- Missing caching: no cache headers on static assets, no revalidation
  strategy, refetching identical data on every mount.

## Reliability

- **Loading and error states**: every async data path in the UI should have
  three visual states (loading / error / empty-or-loaded). A path that
  renders nothing while loading and crashes on error is the single most
  common vibe-coded reliability gap.
- **Rate limiting**: public API endpoints, auth endpoints, and anything
  hitting a paid third-party API should be rate limited (see
  [guardrails-reliability.md](guardrails-reliability.md) for the security
  angle on this).
- **Logging and monitoring**: structured logging vs just `console.log`? Any
  error reporting (Sentry or equivalent)? An app with no observability isn't
  production ready even if the code is clean.
- **Timeouts and retries**: external API calls with no timeout hang
  indefinitely under a degraded upstream. Suggest retry-with-backoff for
  idempotent calls only — retrying a non-idempotent write is worse than
  failing.
- **Graceful shutdown**: long-running servers that don't handle SIGTERM
  drop in-flight requests on deploy. Worth noting for containerized apps.

## Deploy & config readiness

The theme: code that works on one laptop isn't the same as code that works
on a server it's never seen. Most of these gaps are invisible until the
first deploy fails.

### Environment configuration

- `.env.example` should exist and list every env var the code actually
  reads. Build it from real usage — grep for `process.env.X`,
  `import.meta.env.X`, `os.environ[...]` — never from the contents of a real
  `.env`. One of the highest-value small fixes, and safe to auto-fix.
- Flag env vars read in code but missing from `.env.example`, and stale vars
  in `.env.example` no longer used anywhere.
- `process.env.API_KEY` used directly with no check means a missing var
  fails at runtime with a confusing error instead of at boot with a clear
  one — suggest (or add, if an obvious startup module exists) startup
  validation that fails fast with a readable message.

### Hardcoded values

- `localhost`/`127.0.0.1`/specific ports baked into source. Safe to
  auto-fix: replace with an env-driven value defaulting to the current
  localhost value (keeps local dev working unchanged), add the var to
  `.env.example`.
- Hardcoded absolute filesystem paths — break on any other machine.
- Hardcoded staging/production URLs or IDs that should be environment
  specific.

### Build and run

- Does the project have a working `build` and `start` script? A build that
  fails is a critical finding — better to discover it here than mid-deploy.
- `NODE_ENV`/equivalent handled correctly — dev-only middleware, verbose
  error output, and debug tooling gated so they don't ship.
- Are build artifacts and `node_modules` gitignored?

### Operational basics

- Health check endpoint (`/health`) — most hosting platforms want one. Safe
  to auto-fix on a server app that has none.
- CI: any automated check on push? Flag if absent rather than adding one — a
  poorly guessed CI config that fails constantly is worse than none.
- Dockerfile, if present: running as root, secrets baked into layers via
  `ENV`/`ARG`, `latest` base image tags, missing `.dockerignore` (which can
  copy `.env` and `node_modules` into the image).
- Database migrations: a migration system, or a hand-created schema? No
  migration history is a real deploy risk.

## Accessibility

Scope to high-impact, objectively-checkable issues — a full WCAG audit is a
different, much larger job. Say so in the report if the user needs real
compliance.

- Images without `alt` (decorative images should have `alt=""`, not a
  missing attribute). Adding `alt=""` to clearly decorative images is safe;
  descriptive alt text for content images requires knowing what the image
  shows — flag those with file/line.
- Form inputs with no associated `<label>`/`aria-label` — breaks screen
  readers entirely on forms, worth calling out at "medium" severity even on
  a signup/checkout flow.
- Clickable `<div>`/`<span>` used instead of `<button>`/`<a>` — not
  keyboard-reachable, not announced correctly. Converting can change
  styling, so flag rather than auto-fix unless the element has no styling
  dependency.
- Missing `lang` attribute on `<html>`, missing page `<title>`.
- Heading hierarchy that skips levels or has no `<h1>`.

## Dependency health

- Run the ecosystem's audit tool and summarize by severity, with the
  specific packages behind any critical/high findings.
- Fixable by patch-level bump without breaking changes: safe to auto-fix,
  but re-run the build/tests afterward — revert and flag if tests fail.
- Requiring a major/minor bump or with no fix available: always flag. Major
  bumps can silently break behavior.
- Check whether the vulnerability is actually reachable before ranking it
  critical — a high-severity advisory in a transitive dev-only dependency
  that never runs in production is a different risk than one in the
  request-handling path.
- Unmaintained or deprecated dependencies: not urgent, but relevant to
  "production ready" over time.

## What to auto-fix vs. flag

**Auto-fix when mechanical and low-risk** — one reasonable way to do it, and
it can't plausibly change intended behavior: stray debug statements,
`.env.example` generation, hardcoded localhost replacement, unhandled
rejections where the correct handling is unambiguous, obvious null-guard
bugs, basic input validation where the shape is already implied downstream,
adding a basic error boundary, trivial dead code flagged by the linter.

**Flag instead of fixing** when the "right" fix requires a judgment call:
business logic bugs, authorization design gaps (route through Audit Mode —
this deserves proof, not a quick patch), anything requiring real credentials
or infra config, architectural changes, performance fixes that trade off
against complexity, non-patch dependency bumps, anything you're not fully
confident you understand.

When in doubt, flag it. A false negative (missed report item) is recoverable;
an unwanted destructive edit is not.

## Ground rules

1. Check `git status` first — know what's already dirty vs. what you
   introduce. If there's no git history, mention it and be more conservative.
2. Never delete user data or files containing data. Never touch git history.
   Never push, deploy, or ship anything. Never write real secret values into
   `.env`/`.env.example`/any committed file. Never install new dependencies
   without asking — running existing installed tooling (`npm audit`, `tsc`,
   `eslint`, the project's own tests) is fine.
3. Every fix must be independently correct, not just "probably fine because
   it matches a pattern."

Findings from this mode go through the same store as everything else:

```bash
python scripts/findings.py meta project --set "<name>"
python scripts/findings.py meta scope --set "Production-readiness pass: error handling, code quality, performance, deploy config, accessibility, dependencies."
python scripts/findings.py report > SECURITY_AUDIT.md
```

Keep severity ranking honest — don't inflate. If the app is genuinely in
decent shape, say so; a report that cries wolf on every project stops being
useful.
