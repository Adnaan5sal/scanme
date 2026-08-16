#!/usr/bin/env python
"""
sarif.py - Normalize SARIF 2.1.0 output from any scanner into scanme records.

Works with anything that emits SARIF: Semgrep, CodeQL, Snyk Code, Trivy,
Checkov, Bandit, ESLint (--format sarif), gitleaks, Grype, and most commercial
scanners. This is what makes scanme a proof-and-fix layer on top of whatever
the user already runs, rather than a competing scanner.

Usage:
    python sarif.py results.sarif                  # human summary
    python sarif.py results.sarif --json           # normalized records
    python sarif.py a.sarif b.sarif c.sarif        # merge multiple scanners

Output record schema:
    fingerprint  str   stable id, survives line-number churn
    rule_id      str
    tool         str   scanner that produced it
    path         str   repo-relative
    line         int
    title        str   short rule name
    message      str   what the scanner said
    snippet      str   the offending source line, if provided
    severity     str   critical|high|medium|low|info  (normalized across tools)
    cwe          list  CWE ids when the scanner supplies them

No third-party dependencies. Standard library only.
"""

import json
import hashlib
import re
import sys
from pathlib import Path

# -- Severity normalization ---------------------------------------------------
# Scanners disagree wildly. SARIF has `level` (error/warning/note/none) but the
# useful signal is usually `properties.security-severity` (a CVSS-style 0-10
# score, the GitHub code-scanning convention that most tools now emit).

_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

_NAME_MAP = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "low": "low",
    "note": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def normalize_severity(result, rule):
    """Prefer numeric security-severity, fall back to explicit names, then level."""
    for holder in (result, rule):
        if not holder:
            continue
        props = holder.get("properties") or {}
        raw = props.get("security-severity")
        if raw is not None:
            try:
                score = float(raw)
            except (TypeError, ValueError):
                pass
            else:
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                if score > 0:
                    return "low"
                return "info"
        # Some tools (Snyk, Trivy) put a word here instead
        for key in ("severity", "problem.severity", "issue_severity"):
            val = props.get(key)
            if isinstance(val, str) and val.lower() in _NAME_MAP:
                return _NAME_MAP[val.lower()]

    level = (
        result.get("level")
        or (rule or {}).get("defaultConfiguration", {}).get("level")
        or "warning"
    )
    return _LEVEL_MAP.get(str(level).lower(), "medium")


# -- Fingerprinting -----------------------------------------------------------
# Line numbers churn constantly - adding an import at the top of a file must not
# make every finding in it look brand new. So the fingerprint is built from the
# rule, the path, and the *content* at the site. Scanner-provided
# partialFingerprints are preferred when present because the scanner knows more
# about its own stability guarantees than we do.

_WS = re.compile(r"\s+")


def _norm(text):
    return _WS.sub(" ", (text or "").strip())


def make_fingerprint(rule_id, path, snippet, partial=None, line=None):
    if partial:
        # Take a deterministic one; SARIF allows several versioned schemes.
        key = sorted(partial.items())[0][1]
        basis = "pf|{}|{}".format(path, key)
    elif snippet:
        basis = "sn|{}|{}|{}".format(rule_id, path, _norm(snippet))
    else:
        # Weakest form: will churn if the same rule fires twice in one file and
        # one of them moves. Acceptable fallback - scanners that omit snippets
        # are rare.
        basis = "ln|{}|{}|{}".format(rule_id, path, line or 0)
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


# -- Rule index ---------------------------------------------------------------


def build_rule_index(run):
    """Rules can live on the driver or on extensions; index them all by id."""
    index = {}
    tool = run.get("tool") or {}
    drivers = [tool.get("driver") or {}]
    drivers.extend(tool.get("extensions") or [])
    for drv in drivers:
        for rule in drv.get("rules") or []:
            rid = rule.get("id")
            if rid:
                index[rid] = rule
    return index


def rule_for(result, index):
    rid = result.get("ruleId")
    if rid and rid in index:
        return index[rid]
    # SARIF also allows referencing by array index
    ref = result.get("rule") or {}
    idx = ref.get("index")
    if isinstance(idx, int):
        values = list(index.values())
        if 0 <= idx < len(values):
            return values[idx]
    return {}


def extract_cwe(rule):
    cwes = []
    tags = ((rule.get("properties") or {}).get("tags")) or []
    for tag in tags:
        m = re.search(r"CWE-?(\d+)", str(tag), re.I)
        if m:
            cwes.append("CWE-" + m.group(1))
    for rel in rule.get("relationships") or []:
        target = (rel.get("target") or {}).get("id", "")
        m = re.search(r"CWE-?(\d+)", str(target), re.I)
        if m:
            cwes.append("CWE-" + m.group(1))
    return sorted(set(cwes))


def text_of(node):
    if not isinstance(node, dict):
        return str(node or "")
    return node.get("text") or node.get("markdown") or ""


# -- Main parse ---------------------------------------------------------------


def parse_sarif(doc, source_name="sarif"):
    records = []
    for run in doc.get("runs") or []:
        index = build_rule_index(run)
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name") or source_name
        tool_version = driver.get("semanticVersion") or driver.get("version") or ""

        for result in run.get("results") or []:
            # Suppressed / baseline-cleared results are not current findings.
            if result.get("suppressions"):
                continue
            if result.get("baselineState") == "absent":
                continue

            rule = rule_for(result, index)
            locations = result.get("locations") or []
            if locations:
                phys = locations[0].get("physicalLocation") or {}
                artifact = phys.get("artifactLocation") or {}
                region = phys.get("region") or {}
                path = artifact.get("uri") or "<unknown>"
                line = region.get("startLine") or 0
                snippet = text_of(region.get("snippet") or {})
            else:
                path, line, snippet = "<unknown>", 0, ""

            path = re.sub(r"^file://", "", path).lstrip("/")

            title = (
                text_of(rule.get("shortDescription") or {})
                or rule.get("name")
                or result.get("ruleId")
                or "unnamed rule"
            )
            message = text_of(result.get("message") or {}) or title

            records.append(
                {
                    "fingerprint": make_fingerprint(
                        result.get("ruleId") or title,
                        path,
                        snippet,
                        result.get("partialFingerprints"),
                        line,
                    ),
                    "rule_id": result.get("ruleId") or title,
                    "tool": "{} {}".format(tool_name, tool_version).strip(),
                    "path": path,
                    "line": line,
                    "title": title.strip()[:200],
                    "message": message.strip(),
                    "snippet": (snippet or "").strip()[:500],
                    "severity": normalize_severity(result, rule),
                    "cwe": extract_cwe(rule),
                }
            )
    return records


def dedupe(records):
    """Same issue found by two scanners = one finding, with both tools credited."""
    merged = {}
    for rec in records:
        fp = rec["fingerprint"]
        if fp in merged:
            existing = merged[fp]
            tools = set(existing["tool"].split(" + ")) | {rec["tool"]}
            existing["tool"] = " + ".join(sorted(t for t in tools if t))
            order = ["info", "low", "medium", "high", "critical"]
            if order.index(rec["severity"]) > order.index(existing["severity"]):
                existing["severity"] = rec["severity"]
            existing["cwe"] = sorted(set(existing["cwe"]) | set(rec["cwe"]))
        else:
            merged[fp] = dict(rec)
    return list(merged.values())


_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def load_records(paths):
    """Read and normalize a list of SARIF files. Raises ValueError on bad input."""
    out = []
    for path in paths:
        p = Path(path)
        if not p.exists():
            raise ValueError("not found: {}".format(path))
        try:
            doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ValueError("{}: not valid JSON ({})".format(path, exc))
        if "runs" not in doc:
            raise ValueError("{}: no 'runs' key - is this SARIF?".format(path))
        out.extend(parse_sarif(doc, p.stem))
    records = dedupe(out)
    records.sort(key=lambda r: (_ORDER.get(r["severity"], 5), r["path"], r["line"]))
    return records


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    as_json = "--json" in argv

    if not args:
        print(__doc__)
        return 2

    try:
        records = load_records(args)
    except ValueError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1

    if as_json:
        print(json.dumps(records, indent=2))
        return 0

    if not records:
        print("No findings in input.")
        return 0

    counts = {}
    for rec in records:
        counts[rec["severity"]] = counts.get(rec["severity"], 0) + 1
    summary = "  ".join(
        "{}: {}".format(k, counts[k])
        for k in ["critical", "high", "medium", "low", "info"]
        if k in counts
    )
    print("{} candidates ({})".format(len(records), summary))
    print("These are CANDIDATES. Nothing is a finding until proven - see Phase 3.\n")

    for rec in records:
        print("[{}] {}".format(rec["severity"].upper(), rec["title"]))
        print("  {}:{}   {}".format(rec["path"], rec["line"], rec["fingerprint"]))
        print("  rule: {}  via {}".format(rec["rule_id"], rec["tool"]))
        if rec["cwe"]:
            print("  {}".format(", ".join(rec["cwe"])))
        if rec["snippet"]:
            print("  > {}".format(rec["snippet"].splitlines()[0][:120]))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
