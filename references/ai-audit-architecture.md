# AI Security Mode — architecture

The full pipeline is real, not a mockup: `python scripts/ai_audit_cli.py scan
demo/ai-vulnshop --root .` runs against a live fixture, finds the three
planted vulnerability classes, and ingests them into the same ledger
`findings.py` uses for every other mode. Verified end to end while building
this, including catching and fixing three real bugs — a false-positive
signal match on a comment, a docstring suppressing its own finding, and a
path-join bug that silently dropped every result. That's the discipline
this section documents honestly: what's implemented and tested vs. what's
designed but not yet built, per doctrine.md principle 5 — never let this
page imply more coverage than actually exists.

## The 12 engines, mapped to what's real

| Engine | Status | Where |
|---|---|---|
| Discovery Engine | ✅ Implemented | `scripts/ai_audit/discovery.py` — static import/pattern detection, no LLM call |
| AI Architecture Mapper | ✅ Implemented | Same file — `ArchSummary`, `discover()` |
| Prompt Analyzer | ✅ Implemented | `scripts/ai_audit/analyzers.py` — `analyze_prompts()` |
| Agent Analyzer | ✅ Implemented | Same file — `analyze_agent_tools()` (permission/validation checks) |
| Tool/MCP Analyzer | ⚠️ Partial | Dangerous-tool-capability detection is real; MCP-specific config-file risk analysis (beyond detecting an MCP config exists) is not yet built |
| RAG Analyzer | ✅ Implemented | Same file — `analyze_rag()`, tenant-filter detection |
| Data Flow Analyzer | ⚠️ Partial | The window-based "does X reach Y with no Z in between" checks in each analyzer are a lightweight version of this. A general cross-file taint tracer (the `User → Prompt → LLM → Tool Router → Filesystem Tool` graph the original spec describes) is not built — that requires a real AST-based call graph, not regex |
| Attack Path Engine | ⚠️ Partial | Same as above — findings state what they trace, they don't yet compose multi-hop chains automatically. Chaining two findings into one worse finding is currently a manual step, same as it is in Audit Mode |
| Evidence Engine | ✅ Implemented | Every finding carries a quoted snippet, file, and line — same discipline as every other mode's proof requirement |
| Risk Engine | ✅ Implemented | Severity assigned per-finding using doctrine.md's blast-radius-times-reachability principle, not by vulnerability category |
| Fix Engine | ⚠️ Not built for AI-specific findings yet | Standard Audit Mode's fix-with-test discipline (AGENTS.md Phase 4) applies once a finding is promoted — there is no AI-specific autofix (e.g., auto-inserting a tenant filter) because that requires knowing the actual tenant model, which is exactly the kind of judgment call doctrine.md principle 8 says shouldn't be automated |
| Regression Test Engine | ⚠️ Not built for AI-specific findings yet | Same reasoning — write the test by hand using the patterns in [test-patterns.md](test-patterns.md), same as any other finding |

## What "TRACEABLE" vs "VERIFIED" actually means here

The CLI tags every finding with a confidence level (stored in the `cwe`
field's `confidence:` tag, since forking the ledger schema for one mode
would break the "one report format" design every other mode relies on):

- **`confidence:traceable`** — the analyzer found a structural path with no
  visible mitigation nearby (roughly AGENTS.md's Tier 2 territory, but not
  automatically promoted — promoting still requires a human or agent to
  confirm the trace has no gap, same as everywhere else in this project).
- **`confidence:potential`** — a weaker signal (e.g., something that looks
  like validation is present nearby, but its actual effectiveness wasn't
  confirmed). Worth a look, not worth reporting as-is.

Neither is `VERIFIED`/Tier 1. **This tool cannot send a live prompt
injection payload to a running model and observe the response** — that
requires API credentials and a live target, which this CLI doesn't assume
you have. Tier 1 for AI-specific findings means what it always means in
this project: you ran something and watched it happen. The RAG finding in
the demo fixture got there the honest way — not just traced, but watched
live: running `demo/ai-vulnshop/app.py` directly shows Globex's
confidential document appearing in Acme's query context in the actual
output, which is why it was promoted to Tier 2 with that as the note
rather than left as an unconfirmed Tier 3 candidate.

## Why static analysis only gets you Tier 2, not Tier 1, for most AI classes

Unlike a SQL injection (`SLEEP(5)` either delays the response or it
doesn't), an actual prompt injection payload's success is probabilistic —
[ai-threats.md](ai-threats.md) says this plainly. A static analyzer can
prove a *structural* path exists (untrusted content reaches the prompt with
no boundary, and the prompt reaches a tool with no validation) without
being able to prove an attacker's specific payload would actually succeed
against a specific model on a specific day. That gap is real, not a
limitation this tool hides — it's why every AI-specific finding here caps
at Tier 2 unless you have a live target to actually run the injection
against.

## Using it

```bash
python scripts/ai_audit_cli.py discover <path>          # map only, no findings
python scripts/ai_audit_cli.py scan <path> --root .      # discover + analyze + ingest
```

Same Phase 3 discipline as every other mode applies immediately after:

```bash
python scripts/findings.py --root . list --status candidate
python scripts/findings.py --root . promote <fp> --tier 2 --note "..."
python scripts/findings.py --root . discard <fp> --reason "..."
```

Then Phase 4/5 (fix-with-test, report) work exactly as documented in
AGENTS.md — AI-specific findings are findings, not a separate category the
rest of the pipeline treats differently.
