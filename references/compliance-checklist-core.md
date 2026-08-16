# Compliance checklist §1–15

Items tagged [code] can be verified by reading source. [confirm] items
require asking the user. [specialist] items require external engagement.

---

## §1 Governance & Security Management [confirm] / [specialist]

All items are [confirm] or [specialist]. Ask the user:

- Is there an information security policy? Who owns it?
- Are security responsibilities assigned (application owner, system owner)?
- Has a risk assessment been performed? When was it last updated?
- Do processes exist for: vulnerability management, change management,
  incident response, business continuity, disaster recovery?
- Are third-party / vendor security processes defined?
- Are policies reviewed periodically (at least annually)?

Items not answered: NOT TESTED. Items confirmed absent: FAIL with risk
rating based on whether the gap leaves the application unprotected in a
specific scenario.

---

## §2 Architecture & Secure Design [confirm] / [code]

[confirm] — ask whether: architecture is documented (data-flow diagrams,
trust boundaries, external integrations, auth model); threat modeling has
been performed; production and development environments are separated;
security is considered during design changes.

[code] — is there a README/architecture doc showing the trust model? Are
production env vars separated from development?

---

## §3 Authentication [code] / [confirm]

[code] — trace auth middleware; check password storage
(bcrypt/argon2id/scrypt, never plaintext/MD5/SHA1); check password-reset
token expiry and single-use enforcement; look for login rate limiting; check
auth error messages don't leak user enumeration; check auth events are
logged.

[confirm] — is MFA enforced for privileged accounts? Can compromised
credentials be revoked? Are inactive accounts blocked from authenticating?

---

## §4 Authorization & Access Control [code] / [confirm]

[code] — highest priority, most commonly missed. Look for ownership checks
in handlers (`findOne({_id, userId})` pattern — never trust client-supplied
IDs alone). Check every endpoint that takes a resource ID for object-level
authorization. Check admin endpoints for role checks. Look for privilege
escalation paths (can a user pass `role=admin` in a request body?).

[confirm] — is the authorization model documented? Have horizontal/vertical
privilege escalation been explicitly tested? Is tenant isolation tested? Are
permission changes audited?

---

## §5 Session Management [code]

Check session identifiers are crypto-random, not sequential; session expiry
and idle timeout configured; logout invalidates sessions; new session ID
issued on login (fixation); cookie flags (`Secure`, `HttpOnly`, `SameSite`);
sensitive operations re-authenticate.

---

## §6 Input Validation [code]

Look for schema validation (Zod, Joi, Pydantic, express-validator) on
request handlers. Check data types, length limits, numeric ranges enforced.
Check JSON payloads validated before business logic. Confirm client-side
validation is not the only check. Flag any handler accepting `req.body`
without validation.

---

## §7 Injection Protection [code]

SQL: look for raw string concatenation into SQL. NoSQL: check login queries
accept only string email/password, not operators. Command injection: check
`exec`/`spawn` for interpolated input. Template injection: check
server-side template engines for `render(userInput)` patterns.

---

## §8 Cross-Site Scripting (XSS) [code]

Check for `innerHTML`, `dangerouslySetInnerHTML`, `v-html` — the primary
sinks. Check DOM XSS sources (`location.hash`, `document.URL`) feeding
sinks. Confirm stored/user-submitted content is escaped on output. Check CSP
(see [security-headers.md](security-headers.md)).

---

## §9 CSRF Protection [code]

CSRF tokens on state-changing requests where applicable. `SameSite` cookie
policy — the primary modern defense. GET requests don't perform
state-changing actions. Confirm framework CSRF protection hasn't been
disabled.

---

## §10 API Security [code] / [confirm]

[code] — auth enforced on protected endpoints; object-level authorization on
every endpoint taking a resource ID; input validation on request
bodies/params; rate limiting on expensive/sensitive/public endpoints;
request-size limits; CORS correct; errors don't disclose internals; webhooks
authenticated with signature verification.

[confirm] — complete API inventory exists? Deprecated endpoints removed or
protected? Versioning strategy? Idempotency on payment/critical operations?

---

## §11 Database Security [code] / [confirm]

[code] — credentials not in source or committed `.env`; parameterized
queries; connection string from environment, not hardcoded.

[confirm] — database internet-accessible or private network? Least
privilege for DB accounts? Connections encrypted? Backups enabled and access
restricted? Backup restoration tested?

---

## §12 Secrets & Credential Management [code]

One of the highest-value [code] checks. No passwords/API keys/tokens in
source. No secrets in frontend bundles (search `NEXT_PUBLIC_`, `REACT_APP_`,
`VITE_` prefixes). `.env` not committed to git. `.gitignore` includes
`.env`. CI/CD secrets in CI environment, not source.

```bash
grep -rE "(password|api_key|secret|token)\s*[:=]\s*['\"][^${'\"]{8,}" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.go" .
```

---

## §13 File Upload Security [code] / [confirm]

If the app accepts uploads: file type validated by MIME + extension; size
restricted; file names sanitized; no path traversal to system paths; stored
outside web root / not executable; private files require authorization.

If no upload functionality exists, mark N/A.

---

## §14 Frontend Security [code]

HTTPS enforced; security headers present; third-party scripts reviewed for
SRI (`integrity` attribute); secrets absent from frontend code; sensitive
data not in `localStorage`; debug/dev functionality disabled in production;
production errors don't expose stack traces; open redirects prevented;
user-generated content safely rendered; source maps not publicly accessible
if they leak source.

---

## §15 HTTP Security Headers [code]

Read the server/platform config and check response headers — see
[security-headers.md](security-headers.md) for the full method.

| Header | Required value |
|--------|----------------|
| `Strict-Transport-Security` | `max-age=31536000` minimum |
| `Content-Security-Policy` | Present; `default-src 'self'` baseline |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | Deny unused features |
| `frame-ancestors` / `X-Frame-Options` | `'none'` or allowlist |

Absence of `Content-Security-Policy` or `Strict-Transport-Security` is HIGH.
Absence of the others is MEDIUM.
