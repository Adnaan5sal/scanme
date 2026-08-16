# Guard Mode & fast pass — prevention, not just detection

Everything else in this skill finds and proves problems that already exist.
Guard Mode is the other half: applying the same knowledge *while the code is
being written*, so the gap never makes it into a commit in the first place.

## Two ways to use this

**Guard Mode — inline, while writing code.** Whenever you're about to write or
are actively writing code that touches auth, user data, an API boundary, file
uploads, or payments, apply the relevant checks from
[guardrails-security.md](guardrails-security.md) and
[guardrails-reliability.md](guardrails-reliability.md) *before* the code is
finished — the way you'd apply a style guide, not as a separate step
afterward. If you're about to write `Model.findById(req.params.id)` with no
ownership scoping, that's the moment to add the scoping, not a finding for
later.

**Fast pass — an explicit quick check before shipping.** When the user asks to
harden, review, or check something before deploy but doesn't need the full
proof-tiered Audit Mode (Phase 0–5), work the same two guardrail checklists
against the existing codebase and route findings through the normal pipeline:

```bash
python scripts/findings.py meta project --set "<name>"
python scripts/findings.py meta scope --set "Guard-mode pass: guardrails-security.md and guardrails-reliability.md checklists against <what you reviewed>."
# for each gap found:
python scripts/findings.py ingest ...   # or record manually, then:
python scripts/findings.py promote <id> --tier 1 --note "..."
python scripts/findings.py fix <id> --test <path>     # if fixed
python scripts/findings.py scorecard
python scripts/findings.py report > SECURITY_AUDIT.md
```

**There is one report format, not two.** Earlier drafts of this had the fast
pass produce its own separate `SHIELD_PASS.md` with a different table
layout — that meant a user could get two different-looking documents claiming
to describe the same codebase, which is exactly the kind of inconsistency
that erodes trust in a report. Everything, from every mode, funnels into the
same finding store and the same `scorecard`/`report` output.

The fast pass is faster but weaker evidence than full Audit Mode: it's this
model's own judgment applied to a checklist, not a systematic proof-tiered
hunt. Say so. If the user needs stronger sign-off before an actual launch,
recommend the full Audit Mode workflow even if the fast pass came back clean.

## What "Guard Mode" actually means — be precise about this

The name invites overclaiming, and overclaiming is how security tooling loses
trust: **this reduces the rate at which common, well-understood mistakes get
written. It does not make an application invulnerable, and never say or imply
that it does.** Novel vulnerabilities, business-logic flaws, and anything
outside the checklist will still happen. What Guard Mode buys is that the
*predictable* stuff — the missing ownership check, the plaintext password,
the secret in the client bundle — doesn't make it into the code in the first
place, because it was caught at the moment of writing.

## Scope

Security is the core — see [guardrails-security.md](guardrails-security.md)
for authentication, authorization, injection, secrets, CORS, SSRF, and file
upload guardrails. This is the same nine-ish vulnerability classes covered in
[vulnerability-classes.md](vulnerability-classes.md), from the opposite
angle: that reference is written for *hunting and proving* a vulnerability
that already exists; this one is written for *not writing it in the first
place*. Cross-reference rather than duplicate — if you need the deeper "how
would an attacker actually exploit this" detail while writing code, go read
the audit-mode reference.

Reliability is included where it's security-adjacent — see
[guardrails-reliability.md](guardrails-reliability.md) for rate limiting,
timeouts, and safe error handling. Pure polish (loading states, bundle size,
`.env.example` hygiene, dependency housekeeping) is
[production-readiness.md](production-readiness.md) territory, not here —
don't duplicate that ground.

Explicitly out of scope for Guard Mode, because it can't be judged from code
alone: infrastructure/network config, CI/CD pipeline security,
backup/disaster-recovery practice, and formal compliance review. That's
Compliance Mode territory — see
[compliance-checklist-core.md](compliance-checklist-core.md) and the two
files after it.

## How to apply a guardrail without being annoying about it

Don't narrate every check you're silently applying — that turns Guard Mode
into noise the user tunes out, and tuned-out guidance stops working. Apply
guardrails the way you'd naturally hash a password or parameterize a query,
without announcing it. **Do** surface it explicitly when:

- You're making a judgment call the user might want to weigh in on (choosing
  a session strategy, deciding how strict a rate limit should be).
- You notice something adjacent to what you're building that's already
  vulnerable — flag it, but don't silently start fixing unrelated code the
  user didn't ask you to touch this session; mention it and ask.
- A guardrail would meaningfully change the approach (the user asked for
  client-side-only validation and you're adding server-side too) — say what
  you added and why in one line, not a lecture.

## Wiring Guard Mode permanently (one-time setup)

Guard Mode as a skill engages when a request matches its description. It will
not catch a vulnerable pattern introduced through a quick edit that was never
framed as "build a feature" — exactly where guardrails otherwise get skipped.

`scripts/install_guard.sh` closes that gap by registering a `PreToolUse` hook
that runs `scripts/guard.py` on every Write/Edit:

```bash
bash scripts/install_guard.sh
```

The hook **reads the code about to be written** and, when it matches one of
its patterns, injects the specific guardrail for that pattern into context —
IDOR, SQL/command injection, plaintext passwords, mass assignment, XSS sinks,
hardcoded and client-exposed secrets, wildcard CORS, error leakage, missing
cookie flags, unpinned JWT algorithms, path traversal, SSRF, `eval`, NoSQL
auth bypass.

Three properties make it safe to leave on permanently:

- **Silent unless it matches.** Each check carries a veto pattern, so
  `findById` scoped to `req.user.id` produces nothing, and a secret read from
  `process.env` produces nothing. A hook that fires constantly gets muted,
  and a muted guardrail protects nothing.
- **Never blocks.** It only ever adds context. Any exception is swallowed and
  it exits 0, so a bug in the guard can't wedge an edit.
- **Skips where the patterns are expected** — test files, fixtures,
  migrations, `node_modules`, and non-code extensions.

The installer smoke-tests the script before touching settings, backs up
`settings.json` first, preserves any hooks already there, is idempotent, and
supports `--uninstall`. Installing a global hook is a machine-wide change —
offer to run it, don't run it silently just because this skill is installed.

## Fast-pass continuity across sessions

Same as Audit Mode: check the finding store and any existing
`SECURITY_AUDIT.md` before starting a fast pass. Previously fixed items get
spot-checked, not re-proven from scratch; previously open items get
prioritized. See Phase 0 in `SKILL.md`.
