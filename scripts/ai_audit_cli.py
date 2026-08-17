#!/usr/bin/env python
"""
ai_audit_cli.py - AI/Agent Security Auditor CLI.

Orchestrates: Discovery Engine -> Prompt/Agent-Tool/RAG Analyzers -> ingest
into scanme's existing finding ledger (scripts/findings.py) -> scorecard/
report/dashboard, exactly like the standard Audit Mode pipeline. One
ledger, one report format - AI-specific findings and standard web
vulnerability findings live in the same store and the same report.

    python ai_audit_cli.py discover <path>          # architecture map only
    python ai_audit_cli.py scan <path> [--root .]   # discover + analyze + ingest
    python ai_audit_cli.py scan <path> --json        # print candidates, don't ingest

What this is NOT: a live LLM tester. It cannot send an actual prompt
injection payload to a running model and observe the response (Tier 1
reproduction for AI-specific classes) - that requires API credentials and a
live target this CLI doesn't assume. What it produces is Tier 2 material:
structural evidence that a dangerous path exists, quoted with file and
line. Promoting a candidate to `proven` still requires the same judgment
AGENTS.md Phase 3 always requires - confirm the trace has no gap, or
actually exercise it against a live instance if one is available.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "ai_audit"))

from ai_audit.discovery import discover  # noqa: E402
from ai_audit.analyzers import analyze_prompts, analyze_agent_tools, analyze_rag  # noqa: E402


def cmd_discover(args):
    summary = discover(args.path)
    print("\n".join(summary.summary_lines()))
    if summary.prompt_assembly_files:
        print("\n  Prompt-assembly files (Prompt Analyzer targets):")
        for f in summary.prompt_assembly_files:
            print("    -", f)
    if summary.tool_definition_files:
        print("\n  Tool-definition files (Agent/Tool Analyzer targets):")
        for f in summary.tool_definition_files:
            print("    -", f)
    if summary.rag_files:
        print("\n  Retrieval files (RAG Analyzer targets):")
        for f in summary.rag_files:
            print("    -", f)
    return 0


def cmd_scan(args):
    summary = discover(args.path)
    print("\n".join(summary.summary_lines()))

    if not summary.is_ai_app():
        return 0

    print("\nRunning analyzers...")
    # discovery.py stores paths relative to the scanned target (for a clean
    # display in summary_lines()); the analyzers open real files, so join
    # them back against the target root before use. A silent path mismatch
    # here was caught by testing against the demo fixture - _lines() was
    # failing OSError-and-returning-empty for every file, which produced
    # zero findings with no error, exactly the kind of silent gap this
    # project's own doctrine (principle 5) warns against.
    def _full(rels):
        base = Path(args.path)
        return [str(base / r) for r in rels] if rels else _all_code_files(args.path)

    findings = []
    findings += analyze_prompts(_full(summary.prompt_assembly_files))
    findings += analyze_agent_tools(_full(summary.tool_definition_files))
    findings += analyze_rag(_full(summary.rag_files) if summary.rag_files else [])

    seen = {}
    for f in findings:
        seen[f["fingerprint"]] = f
    findings = list(seen.values())
    findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f["severity"], 4))

    print("{} candidate(s) found:\n".format(len(findings)))
    for f in findings:
        print("[{}] {}".format(f["severity"].upper(), f["title"]))
        print("  {}:{}   ({})".format(f["path"], f["line"], f["rule_id"]))
        conf = [c for c in f["cwe"] if c.startswith("confidence:")]
        print("  {}".format(conf[0].split(":")[1].upper() if conf else "?"))
        print()

    if args.json:
        import json
        print(json.dumps(findings, indent=2))
        return 0

    if not findings:
        print("No candidates. Either the app is clean at this pass, or the")
        print("static heuristics here don't cover its pattern - this is not")
        print("proof of absence, see AGENTS.md 'what this doesn't do'.")
        return 0

    import tempfile
    import json
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tf:
        json.dump(findings, tf)
        tmp_path = tf.name

    findings_py = str(Path(__file__).resolve().parent / "findings.py")
    import subprocess
    result = subprocess.run(
        [sys.executable, findings_py, "--root", args.root, "ingest", tmp_path,
         "--label", "AI Security scan: {}".format(args.path)],
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
    Path(tmp_path).unlink(missing_ok=True)

    print("Next: python findings.py --root {} list --status candidate".format(args.root))
    print("Then Phase 3 discipline applies - promote what you trace end to end,")
    print("discard the rest with a reason. Nothing here is 'proven' yet.")
    return 0


def _all_code_files(root):
    from ai_audit.discovery import _iter_files
    return [str(p) for p, kind in _iter_files(root) if kind == "code"]


def main(argv):
    p = argparse.ArgumentParser(prog="ai_audit_cli.py")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("discover", help="map the AI/agent architecture, no findings")
    s.add_argument("path")
    s.set_defaults(func=cmd_discover)

    s = sub.add_parser("scan", help="discover + analyze + ingest into the ledger")
    s.add_argument("path")
    s.add_argument("--root", default=".", help="project root for the finding ledger")
    s.add_argument("--json", action="store_true", help="print candidates as JSON, don't ingest")
    s.set_defaults(func=cmd_scan)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
