---
name: scanme
description: >
  Full-spectrum security, compliance, and production-readiness skill for web
  apps and AI-assisted / "vibe coded" codebases. Its core is a proof-based
  vulnerability audit that reports only findings it has actually reproduced
  or traced, and fixes them with a regression test that fails before the fix
  and passes after — plus inline guardrails while code is being written, a
  35-section formal compliance audit, AI/LLM-specific threat modeling, CSP
  and security-header generation, standing security test suites, a broader
  production-readiness pass (error handling, performance, deploy config,
  accessibility, dependencies), and an autonomous multi-agent "swarm" mode
  (parallel specialist subagents, sandboxed exploit execution, live/browser
  dynamic testing with an authorization gate for third-party targets, an
  HTML dashboard, and auto-fix PRs). Use whenever the user asks for a
  security audit, penetration-style review, vulnerability scan, "find
  security issues", "is my app safe to ship", "harden this", "make this
  production ready", "compliance audit", "SOC 2 / ISO 27001 / PCI DSS
  readiness", "launch checklist", "is my AI app secure", "prompt injection",
  "add security headers" / CSP, "write me security tests", "multi-agent
  pentest", "autonomous security testing", a dashboard of findings, or wants
  exposed secrets, SQL injection, XSS, IDOR/broken access control, SSRF, or
  auth bypasses found and fixed. Also use when a previous scanner produced a
  pile of findings and the user wants to know which ones are real, or when
  the user wants guardrails applied automatically while building auth/API/
  payment code. All modes share one proof discipline and one finding store —
  it will not report a finding it cannot demonstrate.
---

# scanme

**The methodology, all 8 modes, and every reference file live in
[AGENTS.md](AGENTS.md) — read that first.** It's written to be agent-
agnostic (works identically in Cursor, Aider, Codex CLI, or any tool that
can read a file and run shell commands), so nothing here duplicates it.

This file exists only because Claude Code specifically discovers skills by
this filename and frontmatter, and because three pieces of the full
methodology genuinely are Claude-Code-specific implementation detail:
Agent tool syntax, Browser MCP tool names, and the `PreToolUse` hook
mechanism. Everything else — the proof discipline, the eight modes, the
finding store, the scripts — is identical whether you're using Claude Code
or something else, and is documented once, in AGENTS.md, not here.

## Claude Code specifics

### Swarm Mode's parallel agents

Where [AGENTS.md](AGENTS.md#swarm-mode--autonomous-multi-agent-testing)
says "if your tool has a sub-task/sub-agent capability" — in Claude Code
that's the `Agent` tool. Spawn the Injection-hunter, Auth-hunter, and
Client-side personas as three `Agent` tool calls in the same message (real
concurrency, not simulated sequencing), each given the Phase 1 surface map
as context. The Recon and Chain-hypothesis agents run solo, not in
parallel — see [references/agent-personas.md](references/agent-personas.md)
for why.

### Browser-based dynamic testing

Where AGENTS.md says "whatever browser automation your agent has" — in
Claude Code that's the `mcp__Claude_Browser__*` tools (`navigate`,
`computer`, `read_network_requests`, `read_console_messages`,
`javascript_tool`). Use these for the Client-side persona's XSS/CSRF/network
testing described in
[references/live-testing.md](references/live-testing.md).

### Guard Mode hook

To wire [Guard Mode](AGENTS.md#guard-mode--while-code-is-being-written) as
an automatic, permanent check on every file write:

```bash
bash scripts/install_guard.sh
```

This registers a `PreToolUse` hook in `~/.claude/settings.json` that runs
`scripts/guard.py` on every Write/Edit — silent unless a pattern matches,
never blocks, backs up your settings first, supports `--uninstall`. This is
Claude-Code-specific; if you're on another tool, point its equivalent
pre-write hook mechanism (Cursor rules, etc.) at `scripts/guard.py` the same
way, or apply the Guard Mode checklist manually.

Installing a global hook is a machine-wide change — offer to run it, don't
run it silently just because this skill is installed.

---

Read [AGENTS.md](AGENTS.md) for everything else: the one rule, scope and
authorization, all five Audit Mode phases, and the other seven modes.
