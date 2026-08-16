# Security response headers — CSP, HSTS, and the rest

Generate, verify, and deploy security response headers tailored to what the
application actually loads, rather than a generic copy-paste policy.

## Why generic policies fail

Every "copy this CSP" snippet on the internet either breaks the site or is so
permissive it does nothing. `default-src 'self'` blocks your fonts, your
analytics, and your CDN libraries. `script-src 'unsafe-inline' 'unsafe-eval'
*` passes a header scanner while providing essentially no protection against
XSS, which is the entire point of CSP.

A useful policy can only be derived from what the application *actually*
loads. So the work here is inventory first, policy second, verification
third — and the verification step is not optional, because a CSP that breaks
the site in production gets ripped out entirely, which leaves the app worse
off than before.

## Step 1 — Inventory what the app actually loads

The policy is only as good as this list. Every origin you miss becomes a
broken feature in production; every origin you add without checking weakens
the policy.

### Static inspection

Grep the HTML/templates/components for:

| What | Feeds which directive |
|---|---|
| `<script src=...>` | `script-src` |
| `<link rel="stylesheet" href=...>`, `@import` | `style-src` |
| `<img src=...>`, CSS `url(...)` on images, favicons | `img-src` |
| `@font-face`, `<link rel="preload" as="font">` | `font-src` |
| `<iframe src=...>`, embeds (YouTube, Maps, Stripe) | `frame-src` |
| `<video>`, `<audio>`, `<source>` | `media-src` |
| `<link rel="preconnect"/"dns-prefetch">` | strong hint at runtime origins |
| `<form action=...>` pointing off-origin | `form-action` |
| Service worker / `new Worker(...)` | `worker-src` |

Also find, because they decide whether the policy can be strict at all:

- **Inline `<script>` blocks** — including framework-injected ones (Next.js
  hydration data, analytics snippets, JSON-LD).
- **Inline `<style>` blocks and `style="..."` attributes** — very common in
  component libraries and CSS-in-JS, and the usual reason `style-src` ends
  up needing `unsafe-inline`.
- **Inline event handlers** (`onclick=`, `onerror=`) — blocked by any CSP
  without `unsafe-inline`, and they can't be nonce'd. If present, they must
  be refactored to `addEventListener` or the policy stays weak.

### Runtime inspection — do this if the app can be run

Static grep misses the origins that matter most, because SDKs load further
resources at runtime. Load the app in a browser, exercise the main flows, and
collect the actual requests — log in, open modals, submit a form, trigger an
upload, load an embedded video. Analytics, error reporting (Sentry), tag
managers, payment widgets (Stripe), map embeds, and chat widgets all pull
additional origins that never appear in the HTML source.

```js
[...new Set(performance.getEntriesByType('resource')
    .map(e => new URL(e.name).origin))].sort()
```

Specifically check `fetch`/`XHR`/WebSocket targets (`connect-src`) — invisible
to static HTML inspection and the most commonly missed directive.

### Produce the inventory

```
script-src   : 'self', https://cdn.example.com, https://www.googletagmanager.com
style-src    : 'self', https://fonts.googleapis.com  [+ inline styles present]
font-src     : https://fonts.gstatic.com
img-src      : 'self', data:, https://images.example.com
connect-src  : 'self', https://api.example.com, wss://realtime.example.com
frame-src    : https://js.stripe.com
Inline scripts: 3 (2 framework-injected, 1 analytics snippet)
Inline handlers: none found
eval usage   : none found
```

Note explicitly whether inline scripts can be nonce'd — that single fact
determines whether the resulting policy is genuinely protective or mostly
decorative, and the user should know which they're getting.

## Step 2 — Build the policy

**Baseline to build from**, adding only what the inventory demands:

```
default-src 'self';
script-src 'self';
style-src 'self';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
frame-src 'none';
object-src 'none';
base-uri 'self';
form-action 'self';
frame-ancestors 'none';
upgrade-insecure-requests
```

Directives worth understanding rather than copying:

- **`object-src 'none'`** — always set it. Flash/plugin embeds are a legacy
  XSS vector with essentially no modern use case.
- **`base-uri 'self'`** — often forgotten. Without it, an injected `<base>`
  tag can redirect every relative URL on the page to an attacker's origin,
  defeating an otherwise careful `script-src`.
- **`frame-ancestors 'none'`** — the clickjacking control. Supersedes
  `X-Frame-Options`; send both if you care about very old browsers.
- **`form-action 'self'`** — stops an injected form from posting credentials
  off-site.
- **`upgrade-insecure-requests`** — rewrites `http://` subresource requests
  to `https://`. Useful during a migration; harmless after.

### Handling inline scripts, in descending order of preference

1. **Nonces** — a fresh random nonce per response, on each legitimate inline
   script: `script-src 'self' 'nonce-{random}'`. Requires server-side
   rendering, and the nonce **must** be regenerated per request — a static
   nonce is exactly as weak as `unsafe-inline`, which makes it worse than
   useless because it looks secure.
2. **Hashes** — `script-src 'self' 'sha256-...'` for fixed inline blocks.
   Works for static sites. Fragile: the hash changes whenever the inline
   content changes, so re-verify after every build.
3. **`unsafe-inline`** — last resort. If you use it, tell the user directly
   that `script-src` is now providing little XSS protection.

`'strict-dynamic'` with a nonce is worth considering for apps that load
scripts dynamically. **`style-src` is usually the pragmatic compromise** —
many component libraries and CSS-in-JS solutions require `'unsafe-inline'`
for styles, a much smaller risk than inline scripts.

### The rest

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

- **HSTS** — start with `max-age=300` to validate, then raise to a year.
  `includeSubDomains` commits every subdomain to HTTPS; confirm none are
  HTTP-only first. `preload` is effectively irreversible on a useful
  timescale — only suggest it if the user explicitly wants it.
- **`Permissions-Policy`** — deny the features the app doesn't use. An empty
  allowlist `()` denies entirely.
- **`Cross-Origin-Opener-Policy: same-origin`** — isolates the browsing
  context. Can break OAuth popups that rely on `window.opener` — verify login
  flows after adding it.
- **`Cross-Origin-Resource-Policy`** — `cross-origin` on assets legitimately
  embedded by other sites, `same-origin` otherwise.

## Step 3 — Deploy in report-only mode first

This is the step that makes the difference between a policy that ships and
one that gets reverted.

Deploy as `Content-Security-Policy-Report-Only`. The browser reports what
*would* have been blocked without actually blocking it. Exercise the app,
collect the violations, fold legitimate ones into the policy, and only then
switch to enforcing mode. A CSP is one of the few security controls where a
mistake is immediately, visibly user-facing.

## Step 4 — Where to write them

- **Cloudflare Pages / Netlify** — `_headers` file at the output root
- **Next.js** — `headers()` in `next.config.js` for static values, or
  middleware when a per-request nonce is needed (nonces require middleware)
- **Vercel** — the `headers` array in `vercel.json`
- **Express** — `helmet()`, configuring `contentSecurityPolicy.directives`
  explicitly rather than relying on defaults, which are stricter than most
  apps expect and commonly get disabled wholesale when something breaks
- **nginx** — `add_header ... always;` — the `always` flag matters, without
  it the header is omitted on error responses
- **Apache** — `Header always set ...`

## Step 5 — Verify

Confirm both, since either alone can mislead:

1. Headers are present on the **actual response** — platform config can
   silently fail to apply.
2. Nothing broke — no CSP violations in the console, real functionality
   still works. If a hash- or nonce-based policy is in play, verify after a
   rebuild too — hashes change when inline content changes.

```bash
curl -sI https://example.com | grep -iE 'content-security|strict-transport|x-content-type|referrer-policy|permissions-policy|cross-origin'
```

## What headers can and can't do

Security headers are defense in depth: they reduce the impact of a
vulnerability, they don't remove it. A strict CSP can neutralize many XSS
payloads, but the XSS is still there and still worth fixing (see
[vulnerability-classes.md](vulnerability-classes.md)). Headers do nothing for
broken access control, injection reaching the database, or exposed secrets —
usually the more serious problems. A good header grade from an online scanner
is not a security assessment; it measures header configuration only.
