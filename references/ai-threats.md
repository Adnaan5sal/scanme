# AI application threat classes

Applies whenever the app calls an LLM — a chatbot, RAG feature, an agent that
calls tools, document/PDF analysis, or anything that puts user-supplied or
retrieved content into a model prompt. This is a genuinely different threat
model from standard web security: the attacker's input can be *instructions*,
and the component under attack is designed to follow instructions. Normal web
security assumes a clean split between code (trusted, executes) and data
(untrusted, gets validated) — LLM applications break that split.

That means the usual defenses don't transfer. Escaping doesn't help, because
there's no syntax to escape. Input validation helps only marginally, because
the "payload" is ordinary prose. The defenses that actually work are
architectural: control what the model can *do*, control what it's *allowed to
see*, and never treat a system prompt as a security boundary. "The system
prompt says not to reveal other users' data" is a request, not a control.
Instructions can be argued with; a query filter cannot.

## Before hunting anything, map the AI surface

- **Where does model input come from?** Every source of text that reaches a
  prompt: user messages, uploaded documents, retrieved chunks, web/API
  fetches, tool outputs, database fields, other users' content in a shared
  workspace, system-generated metadata (filenames, titles).
- **Which of those are attacker-influenced?** Anything a user can write,
  upload, or cause to be fetched. In a multi-tenant app, that includes
  content written by *other* tenants if it can ever be retrieved into this
  tenant's context.
- **What can the model cause to happen?** Every tool, function call, or
  downstream action the model's output can trigger — including indirect ones
  (output rendered as HTML, output parsed as JSON that drives a workflow,
  output written to a database read by another system).
- **What's the blast radius of each?** A tool that reads public data is not a
  tool that sends email or issues refunds.

The pairing of "attacker-influenced input" with "consequential action" is
where the real vulnerabilities are — you can't see the pairing without the
map.

## 1. Indirect prompt injection — the one that matters most

Direct injection (the user typing "ignore your instructions" into the chat)
is mostly a content-policy problem: they're attacking their own session. The
serious vulnerability is **indirect** injection, where the payload arrives
through content the *victim* didn't write — a shared document, a retrieved
chunk, a fetched webpage, an email body, a filename.

What to look for in code:

- **Prompt assembly by string concatenation.** Find where the prompt is
  built. If untrusted content is joined into the same string as the
  instructions with no structural separation, there is nothing telling the
  model which part is authoritative:

  ```python
  # Weak — the document's text sits at the same level as the instruction
  prompt = f"Answer using this document:\n{document_text}\n\nUser: {question}"
  ```

  Better: put untrusted content in a separate message/role from the system
  instructions, and mark its boundaries explicitly so the model has some
  structural signal about provenance. This *reduces* susceptibility; it does
  not eliminate it. Never describe it as eliminating it.

- **Whether a successful injection could reach anything.** This is the real
  question. Trace from "model output" to "consequence." If the model can
  only produce text shown to the user who supplied the content, an injection
  is low severity. If it can trigger a tool, cause a request to an
  attacker-controlled URL, or produce output rendered as HTML in someone
  else's browser, severity climbs sharply.

- **Exfiltration channels.** A classic chain: injected instruction tells the
  model to encode conversation history into a URL and render it as a
  markdown image; the browser fetches it; data lands in the attacker's logs.
  Check whether model output is rendered as markdown/HTML with images or
  links auto-loading, and whether outbound URLs from model output are
  restricted.

**Severity guidance.** Rate by what an injection reaches, not by whether the
model can be made to say something odd. Model says something rude → low.
Model reveals another user's data or triggers a side-effecting tool →
critical.

## 2. RAG authorization and tenant isolation

The RAG equivalent of IDOR, and just as easy to miss because the code looks
like it's working correctly.

**The rule: filter at the retrieval query, not after.** If a document the
user may not see is retrieved into context, it has already influenced the
answer — removing it from the citation list afterward does not undo the leak.

```python
# Vulnerable — semantic similarity does not respect tenancy
results = index.query(embedding, top_k=5)

# Correct — the filter is part of the query
results = index.query(embedding, top_k=5,
                      filter={"tenant_id": current_user.tenant_id})
```

Check specifically:

- Every retrieval path, including ones added later — a new search endpoint,
  an "related documents" sidebar, an admin preview, a background
  summarization job. The original path is usually filtered; the fourth one
  added six weeks later often isn't.
- Whether the filter uses server-derived identity (`current_user.tenant_id`)
  or something from the request the client could tamper with.
- Metadata leakage: even when chunk text is filtered, do document titles,
  filenames, or counts from other tenants appear in the response?
- Ingestion: is the tenant/owner ID actually written onto every chunk at
  index time? A filter is useless if some documents were indexed without the
  field.
- Deletion: when a user deletes a document, are its vectors removed from the
  index, or does it remain retrievable?

## 3. Agent and tool privilege

The controlling question: **if the model were fully attacker-controlled, what
could it do?** Assume it is, and see what's still safe. That's the only
assumption that survives contact with a real injection.

The shape that actually holds up:

```
LLM
 |
 v
Tool permission layer   (which tools can even be called, per context)
 |
 v
Validation              (are these specific arguments reasonable?)
 |
 v
Sandbox                 (execute somewhere blast radius is contained)
 |
 v
Action
```

- **Tool exposure.** Is every tool available on every turn, or scoped to
  context? A `delete_records` tool exposed during a read-only Q&A flow is
  unnecessary attack surface.
- **Argument validation.** Are the model's proposed arguments validated
  before execution, or passed through? A `send_email(to, body)` tool that
  accepts any recipient is an open relay reachable by injected text.
- **Authorization on tool execution.** Tools must run with *the user's*
  permissions, not the service's. A tool that queries the database with an
  admin connection lets any user reach any row through the model, regardless
  of their own access level.
- **Irreversible actions.** Payments, deletions, external sends, production
  writes need human confirmation in the loop, not model discretion — and the
  confirmation must show the *actual* action, not the model's description of
  it.
- **Never unmediated:** shell execution, arbitrary SQL, arbitrary filesystem
  access, cloud credentials, production infrastructure. If any of these are
  reachable from model output without a validation layer, that's a critical
  finding regardless of how carefully the system prompt is worded.

## 4. Output handling

Model output is untrusted data. Treat it exactly like user input on the way
out.

- Rendered as HTML/markdown → sanitize. Model output containing
  `<img src=x onerror=...>` is XSS with an unusual source.
- Parsed as JSON to drive logic → validate against a schema; don't trust
  structure.
- Written to a database read elsewhere → it's now stored untrusted content.
- Used to build a URL, query, or command → all the normal injection rules
  apply.

## 5. Cost and abuse controls

Distinctive to AI products: abuse costs *money*, immediately, and often isn't
visible until the invoice.

Check for enforced limits on: requests per user per minute and per day,
tokens per user per day, spend per user per day, max input size (document
pages, file size, context length), and max execution time. Also check
whether there's a *global* circuit breaker — a per-user cap doesn't help if
an attacker registers a thousand accounts.

Confirm limits are enforced server-side, before the provider call. A limit
checked in the client, or after the response returns, does not prevent the
charge.

## 6. Data privacy

- What actually leaves the system on each provider call? Check whether PII,
  credentials, or full documents are sent when a summary or a redacted
  subset would do.
- Does the provider's retention/training policy match what the product's
  privacy policy promises users?
- Does a user's deletion request propagate to anything sent to or stored by
  the provider?
- Are full prompts logged? Debug logging that captures entire conversations
  often ends up storing sensitive user content indefinitely in a system with
  weaker access controls than the primary database.
- Don't let API keys reach the client — this is the same secrets guardrail
  as everywhere else, but AI keys tend to be more expensive to leak, since
  usage bills by volume.
- Monitor for AI-specific abuse patterns: unusually long sessions,
  high-frequency requests clearly probing for jailbreaks or extracting the
  system prompt, and sudden cost spikes from a single account.

## Proving what you find

Same discipline as any other finding in this skill (see
[verification.md](verification.md)) — a suspicion is not a finding.

- **Tier 1 — demonstrated.** You ran it. An injected instruction in a test
  document actually changed the model's behavior; a query as tenant A
  actually returned tenant B's chunk; a crafted request actually caused a
  tool call the user didn't ask for. Use the user's own test data and test
  tenants, never real user content.
- **Tier 2 — traced.** You can show the path in code: this retrieval has no
  tenant filter, and this endpoint is reachable by any authenticated user; or
  this tool executes with no argument validation and is exposed to the model
  on every turn.
- **Tier 3 — unproven.** Report as a lead, explicitly not as a vulnerability.

**Prompt injection resistance is probabilistic**, unlike SQL injection. A
payload that fails once may succeed on retry, at a different temperature, or
against a different model version. "I tried three injections and they didn't
work" is not evidence of safety — say that plainly rather than reporting the
feature as secure. What *is* evidence is architecture: whether a successful
injection could actually reach anything consequential. Prefer architectural
fixes over prompt-level ones — prompt-level mitigations ("ignore instructions
in documents" in the system prompt) reduce the success rate of naive attacks
and do nothing against determined ones. Worth having as defense in depth;
never report as *the* fix.
