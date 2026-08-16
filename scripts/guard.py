#!/usr/bin/env python
"""
guard.py - PreToolUse hook that reads the code about to be written and
injects the specific guardrail that applies to it.

This is not a linter and not a blocker. It runs on every Write/Edit, so it has
two hard constraints: it must be fast (single-digit milliseconds of matching),
and it must be quiet. A hook that fires on everything gets muted, and a muted
guardrail protects nothing. So every pattern here is chosen for precision over
recall - better to say nothing than to cry wolf on the fifteenth false positive.

Contract (Claude Code hooks):
    stdin  : {"tool_name": "Write"|"Edit", "tool_input": {...}}
    stdout : {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                     "additionalContext": "..."}}
    exit 0 : always. This advises, it never blocks - a false positive must
             never be able to wedge someone's workflow.

Silent when nothing matches, which is the overwhelmingly common case.

Test it directly:
    echo '{"tool_name":"Write","tool_input":{"file_path":"a.js",
      "content":"User.findById(req.params.id)"}}' | python guard.py
"""

import json
import re
import sys

MAX_BYTES = 400000           # skip generated/minified monsters
MAX_HITS = 4                 # never dump a wall of text into the context

# Files where these patterns are expected and correct, so flagging them is noise.
SKIP_PATH = re.compile(
    r"(^|[\\/])("
    r"node_modules|vendor|dist|build|\.next|__pycache__|\.venv|venv|"
    r"migrations|fixtures|__tests__|__mocks__"
    r")[\\/]"
    r"|\.(md|json|lock|txt|yaml|yml|toml|csv|svg|png|jpg|snap)$"
    r"|\.(test|spec|stories)\.[jt]sx?$"
    r"|(^|[\\/])(test_|conftest)",
    re.I,
)

CODE_EXT = re.compile(r"\.(js|jsx|ts|tsx|mjs|cjs|py|rb|go|php|java|cs|rs|sql)$", re.I)


def _c(pattern):
    return re.compile(pattern, re.I)


# Each check: (id, regex, guardrail message, veto regex or None).
# The veto is what keeps precision high - if it matches anywhere in the same
# content, the finding is suppressed because the mitigation is evidently there.
CHECKS = [
    (
        "idor",
        _c(r"\.(findById|findByIdAndUpdate|findByIdAndDelete|findByPk)\s*\(\s*(?:req|request|ctx)\b"),
        "Object lookup keyed only on a client-supplied id. Scope it to the "
        "authenticated owner instead: findOne({_id: id, userId: req.user.id}) "
        "and 404 on miss. This is broken access control (IDOR) - the most common "
        "serious flaw in app code, and invisible in testing because the owner's "
        "own requests all work.",
        _c(r"userId|user_id|ownerId|owner_id|tenant|req\.user\.id|currentUser"),
    ),
    (
        "sql-concat",
        _c(r"""(?:query|execute|exec|raw)\s*\(\s*(?:["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"']*["']\s*\+|`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^`]*\$\{)"""),
        "SQL assembled by string concatenation or interpolation. Use "
        "parameterized queries - db.query('... WHERE id = $1', [id]) - so the "
        "driver separates code from data. Escaping by hand does not hold.",
        None,
    ),
    (
        "cmd-injection",
        _c(r"\b(exec|execSync|spawnSync|popen|system)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"),
        "Shell command built from interpolated input. Use the array form "
        "(execFile('git', ['log', ref])) so arguments cannot become shell "
        "syntax. Command injection is usually immediate RCE.",
        None,
    ),
    (
        "plaintext-password",
        _c(r"password\s*[:=]\s*(?:req|request)\.(?:body|query|params)\.\w*password"),
        "Password taken straight from the request into storage. Hash with "
        "argon2id (or bcrypt/scrypt) before it touches the database. Never "
        "store or log the plaintext.",
        _c(r"\b(bcrypt|argon2|scrypt|pbkdf2|hashSync)|\.hash\s*\("),
    ),
    (
        "mass-assignment",
        _c(r"(?:Object\.assign\s*\([^)]*\b(?:req|request)\.body|\.\.\.\s*(?:req|request)\.body|(?:create|update|insert|save)\s*\(\s*(?:req|request)\.body\s*\))"),
        "Whole request body written to a model. A client can set fields you did "
        "not intend - role, isAdmin, credits, verified. Pick fields explicitly, "
        "or validate against a schema that strips unknown keys.",
        None,
    ),
    (
        "xss-sink",
        _c(r"(?:\.innerHTML|\.outerHTML)\s*=\s*(?![\"'`])|dangerouslySetInnerHTML|v-html\s*=|insertAdjacentHTML\s*\(\s*[^,]+,\s*(?![\"'`])"),
        "HTML sink fed a non-literal value. If any part of it can reach user "
        "input, that is XSS. Prefer textContent, or sanitize with DOMPurify when "
        "markup is genuinely required.",
        _c(r"DOMPurify|sanitize(Html)?\s*\(|escapeHtml"),
    ),
    (
        "hardcoded-secret",
        _c(r"""(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{16,}["']"""),
        "Literal credential in source. Move it to an environment variable and add "
        "the file to .gitignore. If this has already been committed the value must "
        "be rotated - removing it in a later commit does not remove it from history.",
        _c(r"process\.env|os\.environ|getenv|import\.meta\.env|EXAMPLE|PLACEHOLDER|xxxx|<your"),
    ),
    (
        "client-exposed-secret",
        _c(r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC)_\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)"),
        "Secret behind a client-exposed env prefix. Anything with this prefix is "
        "compiled into the browser bundle and readable by every visitor. Drop the "
        "prefix and use it server-side only. (Publishable/anon keys designed to be "
        "public are the exception.)",
        _c(r"PUBLISHABLE|ANON_KEY|PUBLIC_KEY\b"),
    ),
    (
        "cors-wildcard",
        _c(r"origin\s*:\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*"),
        "Wildcard CORS origin. Combined with credentials this lets any site make "
        "authenticated requests as your logged-in users. Name the allowed origins "
        "explicitly.",
        None,
    ),
    (
        "error-leak",
        _c(r"res\.(?:status\s*\(\s*\d+\s*\)\s*\.)?(?:send|json)\s*\(\s*(?:err|error|e|ex)\s*[,)]"),
        "Raw error object returned to the client. Stack traces and driver errors "
        "disclose file paths, queries, and library versions. Log the detail "
        "server-side, return a generic message plus a correlation id.",
        None,
    ),
    (
        "cookie-flags",
        _c(r"res\.cookie\s*\(|set_cookie\s*\(|new\s+Cookie\s*\("),
        "Cookie being set - confirm httpOnly, secure, and sameSite are all "
        "present. Without httpOnly any XSS reads the session; without secure it "
        "crosses plain HTTP.",
        _c(r"httpOnly|http_only"),
    ),
    (
        "jwt-unpinned",
        _c(r"jwt\.verify\s*\(|jwt\.decode\s*\(|jsonwebtoken.*\.verify\s*\("),
        "JWT verification without a pinned algorithm list. Pass "
        "{algorithms: ['HS256']} - otherwise a token claiming alg:none or a "
        "swapped algorithm can bypass verification entirely. jwt.decode does not "
        "verify at all.",
        _c(r"algorithms\s*:"),
    ),
    (
        "path-traversal",
        _c(r"(?:readFile|readFileSync|createReadStream|sendFile|unlink)\s*\([^)]*\b(?:req|request)\.(?:params|query|body)\b"),
        "Filesystem path built from request input. '../' escapes the intended "
        "directory. Resolve it and assert the result is still inside the base "
        "directory before opening.",
        _c(r"path\.resolve[^;]*startsWith|basename\s*\(|normalize[^;]*startsWith"),
    ),
    (
        "ssrf",
        _c(r"(?:fetch|axios(?:\.\w+)?|urlopen)\s*\(\s*(?:req|request)\.(?:body|query|params)\.\w+"),
        "Outbound request to a client-supplied URL. Block internal ranges - "
        "especially 169.254.169.254, the cloud metadata endpoint, which hands out "
        "IAM credentials. Allowlist hosts if you can.",
        _c(r"169\.254|allowlist|allowedHosts|isPrivate|blocklist"),
    ),
    (
        "eval",
        _c(r"\beval\s*\(|new\s+Function\s*\("),
        "Dynamic code execution. If any input reaches this it is arbitrary code "
        "execution. There is almost always a data-driven alternative.",
        None,
    ),
    (
        "nosql-injection",
        _c(r"findOne\s*\(\s*\{[^}]*(?:password|token)\s*:\s*(?:req|request)\.body"),
        "Credential compared inside a query built from the request body. A posted "
        "{\"$ne\": null} matches any record and logs the attacker in. Coerce to "
        "string before querying, or validate the type first.",
        None,
    ),
]


def read_payload():
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def extract(payload):
    """Return (path, code) for the content about to be written, or (None, None)."""
    tool = payload.get("tool_name") or ""
    ti = payload.get("tool_input") or {}
    if tool == "Write":
        return ti.get("file_path"), ti.get("content") or ""
    if tool in ("Edit", "MultiEdit"):
        if ti.get("edits"):
            joined = "\n".join(e.get("new_string", "") for e in ti["edits"])
            return ti.get("file_path"), joined
        return ti.get("file_path"), ti.get("new_string") or ""
    if tool == "NotebookEdit":
        return ti.get("notebook_path"), ti.get("new_source") or ""
    return None, None


def analyze(path, code):
    if not path or not code:
        return []
    if not CODE_EXT.search(path) or SKIP_PATH.search(path):
        return []
    if len(code) > MAX_BYTES:
        return []

    hits = []
    for check_id, pattern, message, veto in CHECKS:
        m = pattern.search(code)
        if not m:
            continue
        if veto and veto.search(code):
            continue
        line = code.count("\n", 0, m.start()) + 1
        hits.append((check_id, line, m.group(0).strip()[:70], message))
        if len(hits) >= MAX_HITS:
            break
    return hits


def render(path, hits):
    out = [
        "scanme guardrail - {} pattern(s) in the code being written to {}:".format(
            len(hits), path
        ),
        "",
    ]
    for check_id, line, snippet, message in hits:
        out.append("[{}] line ~{}: {}".format(check_id, line, snippet))
        out.append("  {}".format(message))
        out.append("")
    out.append(
        "Apply the fix now, while writing this code, rather than leaving it for an "
        "audit later. If a pattern is a false positive here, proceed - say in one "
        "line why it is safe so the reasoning is on record."
    )
    return "\n".join(out)


def main():
    payload = read_payload()
    path, code = extract(payload)
    hits = analyze(path, code)

    if not hits:
        return 0  # silent: the common case

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": render(path, hits),
        }
    }))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # A guardrail must never break the user's edit. Fail open, always.
        sys.exit(0)
