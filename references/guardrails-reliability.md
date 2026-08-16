# Reliability guardrails (security-adjacent)

Scoped to reliability concerns that double as security concerns — an
unprotected endpoint or a leaked stack trace is both a reliability gap and an
attack surface. Pure UX polish (loading spinners, skeleton screens) is
[production-readiness.md](production-readiness.md) territory, not here.

## Rate limiting

Apply a rate limit at the point of writing any of these, rather than adding
it later as an afterthought:

- **Authentication endpoints** — login, signup, password reset, OTP/email
  verification. These are the highest-value targets for credential stuffing
  and enumeration, and are the ones most often shipped with no limit at all.
- **Anything that costs money per call** — external API calls (especially
  AI/LLM generation), SMS/email sending, payment operations. An unlimited
  endpoint here isn't just abusable, it's a direct line to an unbounded bill.
- **Expensive database operations** — search, export, report generation.
- **Public-facing write endpoints** — contact forms, comments, any endpoint
  that doesn't require auth but accepts input.

A simple in-memory or Redis-backed limiter (attempts per IP or per account
per time window) is enough as a default; the point is having *something*,
not picking the theoretically optimal algorithm. If the framework or
platform has a built-in rate-limiting primitive, prefer it over a custom one.

## Timeouts

- Any outbound call to an external service (third-party API, another
  internal service) should have a timeout. An unbounded call means a slow or
  hung upstream can exhaust your server's request-handling capacity.
- Prefer a timeout that fails fast and returns a clear error over one that
  hangs — a visible failure is recoverable, a silent hang usually means the
  whole request pool eventually locks up.

## Error handling that doesn't leak

- Don't let an unhandled exception in a request handler return a raw stack
  trace, a database error message, or an internal file path to the client.
  Catch at the boundary and return a generic message with an internal
  reference/log ID; put the detail in server-side logs only.
- Every `await` on I/O (database, external API, filesystem) needs a
  reachable failure path — either a surrounding try/catch or a caller that
  handles rejection. An empty or log-only `catch` block that swallows the
  error without surfacing it anywhere is worse than no catch at all, because
  it hides the failure instead of handling it.
- Don't include secrets or tokens in error messages or logs, even in a
  catch block that logs the full error object for debugging — check what
  you're actually logging before shipping it.

## Idempotency for critical operations

- Payment and order-creation endpoints should accept an idempotency key (or
  otherwise be safe to retry) so a network retry or double-click doesn't
  create a duplicate charge or duplicate order.
- Webhook handlers (Stripe, payment providers, etc.) should verify the
  signature before processing, and should be safe to receive the same event
  twice — providers retry on any non-2xx response.

## Input validation as a reliability property, not just a security one

Beyond preventing injection, validating shape and type at the API boundary
(with a schema library — zod, joi, pydantic — or explicit checks) prevents
the far more common failure mode: malformed input reaching business logic
and causing a confusing downstream crash instead of a clean 400 response.
Validate before the data reaches anything else, and reject unexpected extra
fields rather than silently ignoring them.
