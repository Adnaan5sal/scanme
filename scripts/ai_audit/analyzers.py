"""
analyzers.py - Prompt Analyzer, Agent/Tool/MCP Analyzer, RAG Analyzer.

Three focused static-analysis passes over the files discovery.py flagged as
relevant. Each returns Finding records in the same shape scanme's
findings.py ledger already expects (fingerprint, rule_id, tool, path, line,
title, message, snippet, severity, cwe) so they ingest with zero schema
changes - one ledger, one report format, same as every other mode.

Every finding here is a candidate, exactly like scripts/run_scanners.sh
output. Confidence is set structurally (see CONFIDENCE below) but nothing
here is Tier 1 "reproduced" - static analysis proves reachability (Tier 2
at best), never runtime behavior. The CLI and the agent using this module
are responsible for the same Phase 3 discipline as everywhere else:
promote what's actually traced end to end, discard what isn't.
"""

import hashlib
import re
from pathlib import Path

CONFIDENCE_TRACEABLE = "confidence:traceable"
CONFIDENCE_POTENTIAL = "confidence:potential"


def _fp(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _lines(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


# Comments and docstrings routinely explain the exact vulnerability class
# they sit next to (that's good practice - and it's exactly why "is there a
# filter/validation nearby" window checks must not search prose). A
# docstring saying "no tenant filter" contains the word "tenant" without
# there being one. Strip comments/docstrings before any "nearby" search so
# explaining a bug in a comment can't accidentally suppress finding it.
_TRIPLE_QUOTED = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.S)
_LINE_COMMENT = re.compile(r'(?://|#).*$', re.M)


def _strip_prose(text):
    text = _TRIPLE_QUOTED.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    text = _LINE_COMMENT.sub("", text)
    return text


def _finding(rule_id, tool, path, line, title, message, snippet, severity, cwe, confidence):
    return {
        "fingerprint": _fp(rule_id, path, line, snippet[:60]),
        "rule_id": rule_id,
        "tool": tool,
        "path": path,
        "line": line,
        "title": title,
        "message": message,
        "snippet": snippet.strip()[:300],
        "severity": severity,
        "cwe": [cwe, confidence] if cwe else [confidence],
    }


# ============================================================== Prompt Analyzer

_PROMPT_CONCAT = re.compile(
    r"""(?:prompt|messages?|context)\s*=\s*(?:f["']|["'].*?["']\s*\+|`.*\$\{)""", re.I
)
_SYSTEM_PROMPT_ECHO = re.compile(
    r"""(?:return|res\.(?:json|send)|console\.log|print)\s*\(.*(?:system_prompt|systemPrompt|SYSTEM_PROMPT)""",
    re.I,
)
_UNTRUSTED_NAME = r"document|doc_text|retrieved|chunk|web_?content|scraped|file_?content"
_UNSTRUCTURED_UNTRUSTED = re.compile(
    r"""(?:{name})\s*[+]\s*["'`]|"""       # doc_text + "..."
    r"""["'`][^"'`]*["'`]\s*[+]\s*(?:{name})\b|"""  # "..." + doc_text
    r"""["'`].*\{{(?:{name})\}}""".format(name=_UNTRUSTED_NAME),
    re.I,
)


def analyze_prompts(files):
    findings = []
    for path in files:
        lines = _lines(path)
        text = "\n".join(lines)

        for i, line in enumerate(lines, 1):
            if _PROMPT_CONCAT.search(line):
                findings.append(_finding(
                    "ai/prompt-concat", "prompt-analyzer", path, i,
                    "Prompt assembled by concatenation, no structural separation",
                    "Untrusted content and system instructions are joined into one string "
                    "with no role/delimiter boundary. The model has no structural signal for "
                    "which part is authoritative - this is the indirect prompt injection "
                    "surface. Separate untrusted content into its own message/role.",
                    line, "medium", "CWE-1426", CONFIDENCE_TRACEABLE,
                ))

        m = _UNSTRUCTURED_UNTRUSTED.search(text)
        if m:
            line_no = text[:m.start()].count("\n") + 1
            findings.append(_finding(
                "ai/indirect-injection-surface", "prompt-analyzer", path, line_no,
                "Untrusted/retrieved content flows directly into prompt text",
                "Retrieved document or fetched content is concatenated into the prompt "
                "with no boundary marker. If this content is attacker-influenced (a "
                "malicious document, a scraped page, another user's upload), it can carry "
                "text engineered to look like instructions. Severity depends on what the "
                "model can do downstream - trace to Agent/Tool Analyzer findings in this "
                "same file before ranking this critical vs low.",
                lines[line_no - 1] if 0 < line_no <= len(lines) else "",
                "high", "CWE-1426", CONFIDENCE_TRACEABLE,
            ))

        for i, line in enumerate(lines, 1):
            if _SYSTEM_PROMPT_ECHO.search(line):
                findings.append(_finding(
                    "ai/system-prompt-leak", "prompt-analyzer", path, i,
                    "System prompt value reachable in a response/log path",
                    "The system prompt is written to a response, log, or console in a code "
                    "path that may be reachable by a user request. Confirm this isn't a "
                    "debug-only path left enabled, and that the system prompt doesn't "
                    "contain anything sensitive (it should never be treated as a secret "
                    "boundary, but leaking it does hand an attacker your instruction set).",
                    line, "low", "CWE-200", CONFIDENCE_TRACEABLE,
                ))

    return findings


# ========================================================= Agent/Tool/MCP Analyzer

_DANGEROUS_TOOL = re.compile(
    r"""\b(?:def|function|const)\s+\w*(run_command|execute|shell|exec_command|"""
    r"""read_file|write_file|delete_file|fetch_url|http_get|send_email|"""
    r"""query_database|run_sql)\w*\s*\(""", re.I,
)
_HAS_VALIDATION_NEARBY = re.compile(
    r"""(?:validate|sanitiz|allowlist|allow_list|whitelist|assert\s|schema\.|isinstance\(|typeof\s)""",
    re.I,
)
_ARG_TO_SINK = re.compile(
    r"""(?:subprocess\.|os\.system|os\.popen|exec\(|eval\(|open\([^)]*['"]w|requests\.(get|post)|fetch\()""",
)


def analyze_agent_tools(files):
    findings = []
    for path in files:
        lines = _lines(path)
        text = "\n".join(lines)

        for m in _DANGEROUS_TOOL.finditer(text):
            line_no = text[:m.start()].count("\n") + 1
            tool_name = m.group(1)
            window_start = max(0, line_no - 1)
            window_end = min(len(lines), line_no + 25)
            window = _strip_prose("\n".join(lines[window_start:window_end]))

            has_validation = bool(_HAS_VALIDATION_NEARBY.search(window))
            reaches_sink = bool(_ARG_TO_SINK.search(window))

            if reaches_sink and not has_validation:
                findings.append(_finding(
                    "ai/unvalidated-dangerous-tool", "agent-tool-analyzer", path, line_no,
                    "Tool '{}' reaches a dangerous sink with no visible argument validation".format(tool_name),
                    "This tool is exposed to the model (directly callable from its output) "
                    "and its argument appears to reach a dangerous sink (subprocess, file "
                    "write, outbound HTTP, eval) within the next ~25 lines with no "
                    "validation, allowlist, or schema check in between. If the model is "
                    "fully attacker-controlled - the correct assumption per "
                    "references/doctrine.md - this is the tool an injected instruction "
                    "would target.",
                    lines[line_no - 1], "critical", "CWE-306", CONFIDENCE_TRACEABLE,
                ))
            elif reaches_sink:
                findings.append(_finding(
                    "ai/tool-reaches-sink", "agent-tool-analyzer", path, line_no,
                    "Tool '{}' reaches a dangerous sink - confirm validation is sufficient".format(tool_name),
                    "Validation-shaped code is nearby (validate/sanitize/allowlist/assert), "
                    "but confirm it actually constrains the argument before it reaches the "
                    "sink, rather than just being present in the function. Structural "
                    "detection can't tell the difference between real validation and a "
                    "validation function that always returns true.",
                    lines[line_no - 1], "medium", "CWE-306", CONFIDENCE_POTENTIAL,
                ))

        for kw, label in [(r"\bpay\w*\(", "payment"), (r"delete_\w*\(", "deletion"),
                           (r"send_(?:email|message|sms)\(", "external send")]:
            for m in re.finditer(kw, text, re.I):
                line_no = text[:m.start()].count("\n") + 1
                window = _strip_prose("\n".join(lines[max(0, line_no - 10):line_no + 5]))
                if not re.search(r"confirm|approve|human[_-]?in[_-]?the[_-]?loop|require_approval", window, re.I):
                    findings.append(_finding(
                        "ai/missing-human-approval", "agent-tool-analyzer", path, line_no,
                        "Irreversible action ({}) with no human-approval gate nearby".format(label),
                        "This looks like an irreversible or side-effecting action reachable "
                        "from agent/tool output, with no confirmation or human-in-the-loop "
                        "check in the surrounding code. Per doctrine.md's fix discipline, "
                        "this needs a design decision (what confirmation UX, whose approval) "
                        "rather than an autofix - flag it, don't patch it.",
                        lines[line_no - 1], "high", "CWE-862", CONFIDENCE_POTENTIAL,
                    ))

    return findings


# ================================================================ RAG Analyzer

_RETRIEVAL_CALL = re.compile(
    r"""\.(query|search|similarity_search)\s*\(([^)]*)\)""", re.I,
)
_TENANT_FILTER_HINT = re.compile(
    r"""tenant|user_id|userId|owner|workspace|org_id|account_id""", re.I,
)


def analyze_rag(files):
    findings = []
    for path in files:
        lines = _lines(path)
        text = "\n".join(lines)

        for m in _RETRIEVAL_CALL.finditer(text):
            args = m.group(2)
            line_no = text[:m.start()].count("\n") + 1
            if not _TENANT_FILTER_HINT.search(args):
                window = _strip_prose("\n".join(lines[max(0, line_no - 15):line_no + 1]))
                if not _TENANT_FILTER_HINT.search(window):
                    findings.append(_finding(
                        "ai/rag-missing-tenant-filter", "rag-analyzer", path, line_no,
                        "Retrieval call with no visible tenant/owner filter",
                        "This vector search does not appear to filter by tenant, user, "
                        "owner, or workspace, either in the call arguments or the "
                        "surrounding ~15 lines. If documents from multiple users/tenants "
                        "share this index, this is the RAG equivalent of IDOR: a "
                        "similarity match can surface another tenant's content into this "
                        "user's context. The filter must be part of the query itself, not "
                        "a post-hoc check on results - see references/ai-threats.md.",
                        lines[line_no - 1] if line_no <= len(lines) else m.group(0),
                        "high", "CWE-863", CONFIDENCE_TRACEABLE,
                    ))

    return findings
