# ai-vulnshop — AI Security Mode's proof fixture

The AI-app counterpart to `demo/vulnshop` (which proves standard Audit
Mode). Zero dependencies — a fake in-memory LLM and vector store, so this
runs anywhere with no API key.

```bash
python ../../scripts/ai_audit_cli.py scan . --root .
```

## What's planted, and what got found

| Vulnerability | File:line | Detected as |
|---|---|---|
| RAG missing tenant filter — `vector_index.query()` mixes Acme and Globex documents in one index with no tenant argument | `app.py:54` | `ai/rag-missing-tenant-filter`, HIGH, traceable |
| Indirect prompt injection surface — `doc_text` concatenated into the prompt with no structural boundary | `app.py:71` | `ai/indirect-injection-surface` + `ai/prompt-concat`, HIGH/MEDIUM, traceable |
| Unvalidated dangerous tool — `run_command()` reaches `subprocess.run(shell=True)` with no argument validation | `app.py:77` | `ai/unvalidated-dangerous-tool`, CRITICAL, traceable |

Run `python app.py` directly and you can see the RAG leak live in the
output — Globex's confidential layoff memo appears in the context built
for Acme's revenue question, without any exploit code required. That's
what made it possible to promote that finding to Tier 2 with a real trace
rather than leaving it as an unconfirmed candidate — see
[references/ai-audit-architecture.md](../../references/ai-audit-architecture.md)
for why AI-specific findings cap at Tier 2 rather than Tier 1 without a
live model in the loop.
