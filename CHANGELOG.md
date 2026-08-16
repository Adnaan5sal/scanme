# Changelog

All notable changes to this project are documented here.

## [0.1.0] — Initial public release

**Core**
- Proof-tiered vulnerability audit (Audit Mode): map attack surface, run
  scanners, prove or discard every candidate at Tier 1 (reproduced) or
  Tier 2 (traced), fix with a test-first regression, report
- Persistent finding ledger (`scripts/findings.py`) — SQLite-backed,
  tracks the full lifecycle including `regressed` (a fix that silently
  reverted), not just a point-in-time snapshot
- SARIF ingestion (`scripts/sarif.py`) — normalizes output from Semgrep,
  CodeQL, gitleaks, Trivy, or any SARIF-emitting scanner into the ledger
- Self-contained HTML dashboard (`scripts/dashboard.py`) and scorecard/
  report generation, no server required

**Seven additional modes**, sharing the same ledger and report format:
Guard Mode (inline guardrails + optional `PreToolUse` hook), Compliance
Mode (35-section SOC 2/ISO 27001/PCI DSS readiness with sampling strategy
and materiality thresholds), AI Security Mode (prompt injection, RAG
tenant isolation, agent/tool sandboxing), Headers Mode (CSP generation
from actual app inventory), Test Generation (standing authorization-matrix
suites), Readiness Mode (error handling, performance, deploy config,
accessibility, dependencies), Swarm Mode (multi-agent parallel testing,
sandboxed exploit execution, authorization-gated live/browser testing,
auto-fix PRs)

**Agent-agnostic architecture**
- `AGENTS.md` — the canonical methodology, written to work with any AI
  coding agent that can read a file and run shell commands
- `SKILL.md` — thin Claude Code-specific wrapper (frontmatter for
  discovery + the few genuinely Claude-Code-specific pieces: Agent tool
  syntax, Browser MCP tool names, PreToolUse hook mechanism)

**Demo**
- `demo/vulnshop/` — a real, deliberately vulnerable API (zero
  dependencies, Node 22.5+/Python 3 only) proving the full pipeline:
  Semgrep (225 rules) finds nothing on two real vulnerabilities; scanme
  reproduces both, fixes them with regression tests confirmed failing
  before and passing after, and catches a simulated regression precisely

**Documentation**
- `references/doctrine.md` — the judgment layer above the mechanical
  workflow: eight principles on false-positive cost, severity calibration,
  scope honesty, and authorization discipline

---

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Versioning is not yet strictly semver — pre-1.0, expect breaking changes
to the ledger schema or mode structure without a major-version bump.
