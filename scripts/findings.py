#!/usr/bin/env python
"""
findings.py - Persistent finding store for scanme.

A Markdown report is a snapshot. This is a ledger: findings keep their identity
across runs, so the store can answer questions a report cannot -

    Which findings are new since last week?
    Which ones did we fix, and did any of them come BACK?
    How long has this critical been open?
    What did we prove vs. what did we merely discard?

Regression detection is the point. A finding marked `fixed` that reappears in a
later scan is flipped to `regressed` and flagged loudly, because a security fix
that silently reverts is the most dangerous state a codebase can be in - the
team believes it is closed.

Storage: .scanme/findings.db (SQLite, stdlib only, no dependencies).

Quick start:
    python findings.py ingest semgrep.sarif --label "pre-launch"
    python findings.py list --status candidate --severity critical
    python findings.py promote a1b2c3d4 --tier 1 --note "curl repro in test_idor.js"
    python findings.py fix a1b2c3d4 --test tests/security/test_idor.js
    python findings.py diff
    python findings.py report > SECURITY_AUDIT_FINDINGS.md

Status lifecycle:
    candidate  -> scanner or manual entry; unproven, NOT reportable
    proven     -> Tier 1 or 2 evidence exists; reportable
    discarded  -> examined and ruled out; reason required
    fixed      -> patched AND guarded by a regression test
    regressed  -> was fixed, came back. Highest priority.
    accepted   -> known, not fixing, with owner + expiry
    gone       -> no longer reported by scanners, but never verified as fixed
"""

import argparse
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Windows defaults stdout to cp1252, which cannot encode the emoji used in the
# report and raises UnicodeEncodeError the moment output is redirected to a
# file. (Semgrep has the same bug writing SARIF on Windows.) Force UTF-8 so the
# report is identical on every platform.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

DB_DIR = ".scanme"
DB_NAME = "findings.db"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
OPEN_STATUSES = ("candidate", "proven", "regressed")

# -- Scoring ------------------------------------------------------------------
# A single number invites the reading "9/10 means secure", which is exactly the
# false confidence this skill exists to avoid. Two guards against that:
#
#   1. Only PROVEN findings move the score. Unproven candidates never do -
#      otherwise a noisy scanner could tank a grade over things that aren't real.
#   2. The grade always prints beside a coverage line stating what was examined.
#      The score measures what was checked and nothing else; a clean grade on a
#      two-class audit is a statement about two classes.

WEIGHTS = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}

# A regression is worse than an equivalent new bug: someone already believed it
# was closed, so nobody is watching it.
REGRESSION_MULTIPLIER = 1.5
# Accepted risk is still real risk, just consciously owned.
ACCEPTED_MULTIPLIER = 0.5

GRADES = [
    (90, "A", "No proven vulnerabilities in what was examined"),
    (75, "B", "Only minor issues remain"),
    (60, "C", "Meaningful issues present"),
    (40, "D", "Serious issues present"),
    (0, "F", "Critical exposure"),
]

GRADE_DOT = {"A": "🟢", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}
SEV_DOT = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

# Plain-English impact for a reader who is not a security engineer, keyed by CWE
# because that is the one identifier scanners agree on.
CWE_PLAIN = {
    "CWE-89": "An attacker can run their own database commands through your app - reading, changing, or deleting any data it can reach.",
    "CWE-79": "An attacker can run their own JavaScript in your users' browsers, letting them steal sessions or act as those users.",
    "CWE-639": "Any logged-in user can reach other users' private records just by changing an ID in the URL.",
    "CWE-284": "Access controls can be bypassed, letting users reach things they should not.",
    "CWE-287": "The login process can be bypassed or fooled.",
    "CWE-352": "Another website can make your users perform actions on your site without their knowledge.",
    "CWE-918": "An attacker can make your server send requests to internal systems it can reach but they cannot.",
    "CWE-22": "An attacker can read or write files outside the intended folder.",
    "CWE-798": "A password or key is written directly into the source code, so anyone with the code has it.",
    "CWE-327": "Weak or outdated cryptography is in use, so protected data may not actually be protected.",
    "CWE-95": "An attacker can execute their own code on your server.",
    "CWE-943": "An attacker can manipulate database queries to bypass checks or reach other data.",
}


def weight_of(row, force_status=None):
    status = force_status or row["status"]
    w = WEIGHTS.get(row["severity"] or "info", 0)
    if status == "regressed":
        w *= REGRESSION_MULTIPLIER
    elif status == "accepted":
        w *= ACCEPTED_MULTIPLIER
    return w


def score_for(rows, force_status=None):
    """100 minus weighted severity of the given findings, clamped to 0-100."""
    total = sum(weight_of(r, force_status) for r in rows)
    return max(0, min(100, int(round(100 - total))))


def grade_for(score):
    for floor, letter, meaning in GRADES:
        if score >= floor:
            return letter, meaning
    return "F", "Critical exposure"


def plain_impact(row):
    """Best available human explanation of what the finding means."""
    for cwe, text in CWE_PLAIN.items():
        if cwe in (row["message"] or "") or cwe in (row["rule_id"] or ""):
            return text
    title = (row["title"] or "").lower()
    for key, cwe in (("idor", "CWE-639"), ("sql inject", "CWE-89"), ("xss", "CWE-79"),
                     ("traversal", "CWE-22"), ("ssrf", "CWE-918"), ("secret", "CWE-798")):
        if key in title:
            return CWE_PLAIN[cwe]
    return row["message"] or ""


def posture(conn):
    """Before/after picture.

    'Before' scores every finding that was ever proven real, weighed as though
    still open - so a fixed critical still shows the risk that was removed.
    'After' scores only what remains open.
    """
    ever = conn.execute(
        "SELECT * FROM findings WHERE status IN "
        "('proven','fixed','regressed','accepted','gone')"
    ).fetchall()
    still_open = conn.execute(
        "SELECT * FROM findings WHERE status IN ('proven','regressed','accepted')"
    ).fetchall()

    before = score_for(ever, force_status="proven")
    after = score_for(still_open)
    return {
        "before": before,
        "after": after,
        "before_grade": grade_for(before),
        "after_grade": grade_for(after),
        "ever": ever,
        "open": still_open,
    }


def get_meta(conn, key, default=""):
    try:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    except sqlite3.OperationalError:
        return default
    return row["value"] if row else default

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    label       TEXT,
    source      TEXT,
    commit_sha  TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    fingerprint     TEXT PRIMARY KEY,
    rule_id         TEXT,
    tool            TEXT,
    path            TEXT,
    line            INTEGER,
    title           TEXT,
    message         TEXT,
    snippet         TEXT,
    severity        TEXT,
    tier            INTEGER,
    status          TEXT NOT NULL DEFAULT 'candidate',
    first_seen_run  INTEGER,
    last_seen_run   INTEGER,
    fix_test        TEXT,
    fix_commit      TEXT,
    note            TEXT,
    updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    run_id      INTEGER,
    at          TEXT NOT NULL,
    event       TEXT NOT NULL,
    detail      TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_events_fp       ON events(fingerprint);
"""


# -- infrastructure -----------------------------------------------------------


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db_path(root):
    return Path(root) / DB_DIR / DB_NAME


def connect(root, create=True):
    path = db_path(root)
    if not path.exists():
        if not create:
            sys.stderr.write(
                "No finding store at {}.\nRun: python findings.py ingest <file>\n".format(path)
            )
            sys.exit(1)
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def git_sha(root):
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def log_event(conn, fp, run_id, event, detail=None):
    conn.execute(
        "INSERT INTO events (fingerprint, run_id, at, event, detail) VALUES (?,?,?,?,?)",
        (fp, run_id, now(), event, detail),
    )


def resolve(conn, prefix):
    """Accept a fingerprint prefix so users can type 6 chars, not 16."""
    rows = conn.execute(
        "SELECT fingerprint FROM findings WHERE fingerprint LIKE ?", (prefix + "%",)
    ).fetchall()
    if not rows:
        sys.stderr.write("No finding matching '{}'\n".format(prefix))
        sys.exit(1)
    if len(rows) > 1:
        sys.stderr.write(
            "Ambiguous '{}' matches {}: {}\n".format(
                prefix, len(rows), ", ".join(r["fingerprint"] for r in rows[:5])
            )
        )
        sys.exit(1)
    return rows[0]["fingerprint"]


# -- ingest -------------------------------------------------------------------


def load_input(path):
    """Detect and normalize SARIF, native scanme JSON, or npm audit JSON."""
    p = Path(path)
    if not p.exists():
        sys.stderr.write("not found: {}\n".format(path))
        sys.exit(1)
    try:
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        sys.stderr.write("{}: not valid JSON ({})\n".format(path, exc))
        sys.exit(1)

    if isinstance(doc, dict) and "runs" in doc:
        import sarif

        return sarif.parse_sarif(doc, p.stem), "sarif"

    if isinstance(doc, dict) and "vulnerabilities" in doc and "metadata" in doc:
        return npm_audit_records(doc), "npm-audit"

    if isinstance(doc, list):
        if any("fingerprint" not in r for r in doc):
            sys.stderr.write("native JSON records must each have a 'fingerprint'\n")
            sys.exit(1)
        return doc, "native"

    sys.stderr.write(
        "{}: unrecognized format. Expected SARIF, npm-audit JSON, or a native list.\n".format(path)
    )
    sys.exit(1)


def npm_audit_records(doc):
    """npm audit does not emit SARIF; normalize it into the same shape."""
    import hashlib

    # npm says "moderate"; the rest of the store says "medium".
    npm_sev = {"critical": "critical", "high": "high", "moderate": "medium",
               "low": "low", "info": "info"}

    out = []
    for name, v in (doc.get("vulnerabilities") or {}).items():
        sev = npm_sev.get(str(v.get("severity", "info")).lower(), "info")
        detail = ""
        for item in v.get("via") or []:
            if isinstance(item, dict):
                detail = item.get("title") or item.get("url") or ""
                break
        basis = "npm|{}|{}".format(name, detail)
        out.append(
            {
                "fingerprint": hashlib.sha256(basis.encode()).hexdigest()[:16],
                "rule_id": "npm-advisory/{}".format(name),
                "tool": "npm audit",
                "path": "package.json",
                "line": 0,
                "title": "{}: {}".format(name, detail or "vulnerable dependency"),
                "message": "Dependency {} has a {} severity advisory. fixAvailable={}".format(
                    name, sev, v.get("fixAvailable")
                ),
                "snippet": "",
                "severity": sev,
                "cwe": [],
            }
        )
    return out


def cmd_ingest(args):
    root = args.root
    conn = connect(root)
    records, fmt = load_input(args.file)

    cur = conn.execute(
        "INSERT INTO runs (started_at, label, source, commit_sha) VALUES (?,?,?,?)",
        (now(), args.label, "{}:{}".format(fmt, Path(args.file).name), git_sha(root)),
    )
    run_id = cur.lastrowid

    new = updated = regressed = 0
    seen = set()

    for rec in records:
        fp = rec["fingerprint"]
        seen.add(fp)
        row = conn.execute(
            "SELECT status FROM findings WHERE fingerprint=?", (fp,)
        ).fetchone()

        if row is None:
            conn.execute(
                """INSERT INTO findings
                   (fingerprint, rule_id, tool, path, line, title, message, snippet,
                    severity, status, first_seen_run, last_seen_run, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,'candidate',?,?,?)""",
                (
                    fp,
                    rec.get("rule_id"),
                    rec.get("tool"),
                    rec.get("path"),
                    rec.get("line", 0),
                    rec.get("title"),
                    rec.get("message"),
                    rec.get("snippet"),
                    rec.get("severity", "info"),
                    run_id,
                    run_id,
                    now(),
                ),
            )
            log_event(conn, fp, run_id, "discovered", rec.get("tool"))
            new += 1
            continue

        # Seen before. The interesting case: it was supposed to be gone.
        if row["status"] in ("fixed", "gone"):
            conn.execute(
                "UPDATE findings SET status='regressed', line=?, last_seen_run=?, updated_at=? "
                "WHERE fingerprint=?",
                (rec.get("line", 0), run_id, now(), fp),
            )
            log_event(
                conn,
                fp,
                run_id,
                "regressed",
                "was '{}', reappeared in {}".format(row["status"], Path(args.file).name),
            )
            regressed += 1
        else:
            conn.execute(
                "UPDATE findings SET line=?, last_seen_run=?, updated_at=? WHERE fingerprint=?",
                (rec.get("line", 0), run_id, now(), fp),
            )
            updated += 1

    # Anything previously open but absent from this scan is 'gone' - not 'fixed'.
    # The distinction matters: 'gone' means the scanner stopped reporting it, which
    # could equally mean the file was deleted, the rule changed, or the scanner
    # itself regressed. Only a verified fix with a test earns 'fixed'.
    vanished = 0
    if not args.no_close and fmt != "npm-audit":
        rows = conn.execute(
            "SELECT fingerprint FROM findings WHERE status IN ('candidate','proven','regressed')"
        ).fetchall()
        for r in rows:
            if r["fingerprint"] not in seen:
                conn.execute(
                    "UPDATE findings SET status='gone', updated_at=? WHERE fingerprint=?",
                    (now(), r["fingerprint"]),
                )
                log_event(conn, r["fingerprint"], run_id, "vanished", "absent from this scan")
                vanished += 1

    conn.commit()

    print("Run #{}  ({} records from {})".format(run_id, len(records), fmt))
    print("  new:        {}".format(new))
    print("  seen again: {}".format(updated))
    if regressed:
        print("  REGRESSED:  {}  <-- previously fixed, now back".format(regressed))
    if vanished:
        print("  vanished:   {}  (marked 'gone', not 'fixed')".format(vanished))
    print("\nNew findings are CANDIDATES. Prove them before reporting.")
    return 0


# -- status transitions -------------------------------------------------------


def cmd_promote(args):
    conn = connect(args.root, create=False)
    fp = resolve(conn, args.fingerprint)
    conn.execute(
        "UPDATE findings SET status='proven', tier=?, note=?, updated_at=? WHERE fingerprint=?",
        (args.tier, args.note, now(), fp),
    )
    log_event(conn, fp, None, "proven", "tier {}: {}".format(args.tier, args.note or ""))
    conn.commit()
    print("{} -> proven (Tier {})".format(fp, args.tier))
    return 0


def cmd_discard(args):
    conn = connect(args.root, create=False)
    fp = resolve(conn, args.fingerprint)
    conn.execute(
        "UPDATE findings SET status='discarded', tier=3, note=?, updated_at=? WHERE fingerprint=?",
        (args.reason, now(), fp),
    )
    log_event(conn, fp, None, "discarded", args.reason)
    conn.commit()
    print("{} -> discarded: {}".format(fp, args.reason))
    return 0


def cmd_fix(args):
    conn = connect(args.root, create=False)
    fp = resolve(conn, args.fingerprint)
    if not args.test and not args.force:
        sys.stderr.write(
            "Refusing to mark fixed with no regression test.\n"
            "A fix without a test that failed before it is unverified - it is the\n"
            "most common way security fixes silently do nothing.\n"
            "Pass --test <path>, or --force to accept an unguarded fix.\n"
        )
        return 1
    conn.execute(
        "UPDATE findings SET status='fixed', fix_test=?, fix_commit=?, updated_at=? "
        "WHERE fingerprint=?",
        (args.test, args.commit or git_sha(args.root), now(), fp),
    )
    log_event(conn, fp, None, "fixed", "test={} commit={}".format(args.test, args.commit or ""))
    conn.commit()
    print("{} -> fixed (guarded by {})".format(fp, args.test or "NO TEST"))
    return 0


def cmd_accept(args):
    conn = connect(args.root, create=False)
    fp = resolve(conn, args.fingerprint)
    detail = "owner={} until={} reason={}".format(args.owner, args.until, args.reason)
    conn.execute(
        "UPDATE findings SET status='accepted', note=?, updated_at=? WHERE fingerprint=?",
        (detail, now(), fp),
    )
    log_event(conn, fp, None, "accepted", detail)
    conn.commit()
    print("{} -> accepted ({})".format(fp, detail))
    return 0


# -- queries ------------------------------------------------------------------


def fetch(conn, status=None, severity=None, tier=None):
    sql = "SELECT * FROM findings WHERE 1=1"
    params = []
    if status:
        if status == "open":
            sql += " AND status IN ({})".format(",".join("?" * len(OPEN_STATUSES)))
            params.extend(OPEN_STATUSES)
        else:
            sql += " AND status=?"
            params.append(status)
    if severity:
        sql += " AND severity=?"
        params.append(severity)
    if tier:
        sql += " AND tier=?"
        params.append(tier)
    rows = conn.execute(sql, params).fetchall()
    return sorted(rows, key=lambda r: (SEV_ORDER.get(r["severity"], 5), r["path"] or ""))


_MARK = {"regressed": "!!", "proven": " *", "fixed": " +", "accepted": " ~"}


def cmd_list(args):
    conn = connect(args.root, create=False)
    rows = fetch(conn, args.status, args.severity, args.tier)
    if not rows:
        print("No findings match.")
        return 0
    for r in rows:
        mark = _MARK.get(r["status"], "  ")
        tier = "T{}".format(r["tier"]) if r["tier"] else "--"
        print(
            "{} {}  {:<8} {:<10} {} {}:{}".format(
                mark, r["fingerprint"][:8], r["severity"], r["status"],
                tier, r["path"], r["line"],
            )
        )
        print("      {}".format((r["title"] or "")[:96]))
    print("\n{} finding(s).  !! regressed   * proven   + fixed   ~ accepted".format(len(rows)))
    return 0


def cmd_show(args):
    conn = connect(args.root, create=False)
    fp = resolve(conn, args.fingerprint)
    r = conn.execute("SELECT * FROM findings WHERE fingerprint=?", (fp,)).fetchone()
    print("{}  [{}]  {}".format(r["fingerprint"], (r["severity"] or "?").upper(), r["status"]))
    print("  title   : {}".format(r["title"]))
    print("  location: {}:{}".format(r["path"], r["line"]))
    print("  rule    : {}  via {}".format(r["rule_id"], r["tool"]))
    print("  tier    : {}".format(r["tier"] or "unproven"))
    if r["fix_test"]:
        print("  test    : {}".format(r["fix_test"]))
    if r["fix_commit"]:
        print("  commit  : {}".format(r["fix_commit"]))
    if r["note"]:
        print("  note    : {}".format(r["note"]))
    if r["snippet"]:
        print("  snippet : {}".format(r["snippet"].splitlines()[0][:100]))
    print("\n  message : {}".format(r["message"]))
    print("\n  History:")
    for e in conn.execute("SELECT * FROM events WHERE fingerprint=? ORDER BY id", (fp,)):
        print("    {}  {:<12} {}".format(e["at"], e["event"], e["detail"] or ""))
    return 0


def cmd_diff(args):
    """What changed between the last two runs."""
    conn = connect(args.root, create=False)
    runs = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 2").fetchall()
    if len(runs) < 2:
        print("Need at least two runs to diff. Only {} so far.".format(len(runs)))
        return 0
    latest, prior = runs[0], runs[1]
    print("Run #{} ({})  vs  run #{} ({})\n".format(
        latest["id"], latest["started_at"], prior["id"], prior["started_at"]))

    buckets = [
        ("REGRESSED (was fixed, came back)", conn.execute(
            "SELECT * FROM findings WHERE status='regressed' AND last_seen_run=?",
            (latest["id"],)).fetchall()),
        ("NEW in this run", conn.execute(
            "SELECT * FROM findings WHERE first_seen_run=?", (latest["id"],)).fetchall()),
        ("STILL OPEN", conn.execute(
            "SELECT * FROM findings WHERE status IN ('candidate','proven') "
            "AND first_seen_run < ? AND last_seen_run=?",
            (latest["id"], latest["id"])).fetchall()),
        ("NO LONGER REPORTED (unverified)", conn.execute(
            "SELECT * FROM findings WHERE status='gone' AND last_seen_run=?",
            (prior["id"],)).fetchall()),
    ]

    for label, rows in buckets:
        if not rows:
            continue
        print("{}  ({})".format(label, len(rows)))
        for r in sorted(rows, key=lambda x: SEV_ORDER.get(x["severity"], 5)):
            print("   [{}] {}  {}:{}  {}".format(
                r["severity"], r["fingerprint"][:8], r["path"], r["line"],
                (r["title"] or "")[:60]))
        print()
    return 0


def cmd_stats(args):
    conn = connect(args.root, create=False)
    print("Runs recorded: {}".format(conn.execute("SELECT COUNT(*) c FROM runs").fetchone()["c"]))
    print("\nBy status:")
    for r in conn.execute(
        "SELECT status, COUNT(*) c FROM findings GROUP BY status ORDER BY c DESC"
    ):
        print("  {:<12} {}".format(r["status"], r["c"]))
    print("\nOpen by severity:")
    for r in conn.execute(
        "SELECT severity, COUNT(*) c FROM findings "
        "WHERE status IN ('candidate','proven','regressed') GROUP BY severity"
    ):
        print("  {:<10} {}".format(r["severity"], r["c"]))
    reg = conn.execute("SELECT COUNT(*) c FROM findings WHERE status='regressed'").fetchone()["c"]
    if reg:
        print("\n  {} REGRESSED finding(s) - fixes that did not hold.".format(reg))
    return 0


def cmd_scorecard(args):
    """The at-a-glance verdict, for the terminal."""
    conn = connect(args.root, create=False)
    p = posture(conn)
    bg, bmeaning = p["before_grade"]
    ag, ameaning = p["after_grade"]
    project = get_meta(conn, "project", Path(args.root).resolve().name)

    fixed = len(fetch(conn, "fixed"))
    counts = {}
    for r in p["open"]:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    open_desc = ", ".join("{} {}".format(v, k) for k, v in sorted(
        counts.items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))) or "none"

    line = "=" * 62
    print("\n{}\n  SECURITY AUDIT - {}\n{}\n".format(line, project, line))
    print("        BEFORE                        AFTER")
    print("      +---------+                   +---------+")
    print("      |    {}    |    ---------->    |    {}    |".format(bg, ag))
    print("      +---------+                   +---------+")
    print("       {:>3}/100                       {:>3}/100".format(p["before"], p["after"]))
    print()
    print("  Was : {}".format(bmeaning))
    print("  Now : {}".format(ameaning))
    print()
    print("  Proven vulnerabilities found : {}".format(len(p["ever"])))
    print("  Fixed + regression-tested    : {}".format(fixed))
    print("  Still open                   : {}".format(open_desc))

    regressed = [r for r in p["open"] if r["status"] == "regressed"]
    if regressed:
        print("\n  !! {} REGRESSED - a fix that did not hold:".format(len(regressed)))
        for r in regressed:
            print("     {} {}:{}".format(r["fingerprint"][:8], r["path"], r["line"]))

    scope = get_meta(conn, "scope")
    print("\n  Coverage:")
    if scope:
        import textwrap
        plain = scope.replace("`", "")
        for ln in textwrap.wrap(plain, 56):
            print("    {}".format(ln))
    else:
        print("    not recorded - run: meta scope --set \"...\"")
    print("\n  This grade describes what was examined. It is not a claim")
    print("  that anything unexamined is safe.\n")
    return 0


def cmd_meta(args):
    conn = connect(args.root)
    if args.value is None:
        print(get_meta(conn, args.key) or "(unset)")
        return 0
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)",
                 (args.key, args.value))
    conn.commit()
    print("{} = {}".format(args.key, args.value))
    return 0


def _esc(text, limit=None):
    out = (text or "").replace("|", "\\|").replace("\n", " ")
    return out[:limit] if limit else out


def _n(count, singular, plural=None):
    """'1 regression' / '3 regressions' - the report reads like prose, so it
    should not be littered with (s)."""
    word = singular if count == 1 else (plural or singular + "s")
    return "{} {}".format(count, word)


def cmd_report(args):
    """The full audit report, in Markdown, generated from the ledger."""
    conn = connect(args.root, create=False)
    p = posture(conn)
    bg, bmeaning = p["before_grade"]
    ag, ameaning = p["after_grade"]

    project = get_meta(conn, "project", Path(args.root).resolve().name)
    scope = get_meta(conn, "scope")
    not_checked = get_meta(conn, "not_checked")

    fixed = fetch(conn, "fixed")
    still_open = sorted(p["open"], key=lambda r: SEV_ORDER.get(r["severity"], 9))
    unproven = fetch(conn, "candidate")
    discarded = fetch(conn, "discarded")
    runs = conn.execute("SELECT * FROM runs ORDER BY id").fetchall()

    W = print

    # ---- header -------------------------------------------------------------
    W("# 🛡️ Security Audit — {}\n".format(project))
    W("*Generated {} · {} · every finding below was proven before it was "
      "reported.*\n".format(now()[:10], _n(len(runs), "scan run")))
    W("---\n")

    # ---- the verdict --------------------------------------------------------
    W("## The verdict\n")
    W("<table>")
    W("<tr><th width=\"50%\">Before this audit</th><th width=\"50%\">After this audit</th></tr>")
    W("<tr><td align=\"center\"><h1>{} &nbsp; {}</h1><b>{}/100</b><br><sub>{}</sub></td>"
      "<td align=\"center\"><h1>{} &nbsp; {}</h1><b>{}/100</b><br><sub>{}</sub></td></tr>"
      .format(GRADE_DOT.get(bg, ""), bg, p["before"], bmeaning,
              GRADE_DOT.get(ag, ""), ag, p["after"], ameaning))
    W("</table>\n")

    delta = p["after"] - p["before"]
    if delta > 0:
        W("**+{} points.** {} proven {} fixed and locked behind regression tests.\n"
          .format(delta, len(fixed), "vulnerability was" if len(fixed) == 1
                  else "vulnerabilities were"))
    elif not p["ever"]:
        W("**No proven vulnerabilities were found in what was examined.** Read "
          "that precisely: it means nothing was demonstrated, not that the "
          "application is secure.\n")

    counts = {}
    for r in p["ever"]:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1

    W("| | Count |")
    W("|---|---|")
    for sev in ["critical", "high", "medium", "low"]:
        if counts.get(sev):
            W("| {} Proven {} | {} |".format(SEV_DOT[sev], sev, counts[sev]))
    W("| ✅ Fixed + regression-tested | {} |".format(len(fixed)))
    W("| ⚠️ Still open | {} |".format(len(still_open)))
    if unproven:
        W("| 🔍 Unverified leads (not vulnerabilities) | {} |".format(len(unproven)))
    if discarded:
        W("| 🗑️ Candidates ruled out | {} |".format(len(discarded)))
    W("")

    regressed = [r for r in still_open if r["status"] == "regressed"]
    if regressed:
        W("> ### 🚨 {} detected\n>".format(_n(len(regressed), "regression")))
        W("> A fix that was previously verified is no longer in place. This "
          "ranks above new findings of equal severity, because everyone "
          "involved believes it is already closed.\n>")
        for r in regressed:
            W("> - **{}** — `{}:{}`".format(_esc(r["title"]), r["path"], r["line"]))
        W("")

    # ---- scope --------------------------------------------------------------
    W("---\n")
    W("## What was examined\n")
    if scope:
        W(scope + "\n")
    else:
        W("*Scope not recorded. Set it with "
          "`findings.py meta --set scope \"...\"` — a grade without a stated "
          "scope is not meaningful.*\n")
    if runs:
        W("| # | When | What ran |")
        W("|---|------|----------|")
        for r in runs:
            W("| {} | {} | {} |".format(r["id"], (r["started_at"] or "")[:16].replace("T", " "),
                                        _esc(r["label"] or r["source"] or "-", 60)))
        W("")

    # ---- what was wrong, and what was done ---------------------------------
    if fixed or still_open:
        W("---\n")
        W("## What was wrong, and what was done about it\n")
        W("| | Issue | Where | Severity | Proof | Status |")
        W("|---|-------|-------|----------|-------|--------|")
        for r in still_open + fixed:
            status = "✅ Fixed" if r["status"] == "fixed" else (
                "🚨 Regressed" if r["status"] == "regressed" else "⚠️ Open")
            W("| {} | {} | `{}:{}` | {} | {} | {} |".format(
                SEV_DOT.get(r["severity"], ""), _esc(r["title"], 60),
                r["path"], r["line"], (r["severity"] or "").upper(),
                "Tier {}".format(r["tier"]) if r["tier"] else "-", status))
        W("")

        for i, r in enumerate(still_open + fixed, 1):
            W("### {}. {}\n".format(i, r["title"]))
            W("**In plain terms** — {}\n".format(plain_impact(r)))
            W("| | |")
            W("|---|---|")
            W("| **Severity** | {} {} |".format(SEV_DOT.get(r["severity"], ""),
                                                (r["severity"] or "").upper()))
            W("| **Location** | `{}:{}` |".format(r["path"], r["line"]))
            W("| **Found by** | {} |".format(_esc(r["tool"] or "-")))
            W("| **Evidence** | {} |".format(
                "Tier 1 — reproduced against a running instance" if r["tier"] == 1
                else "Tier 2 — traced source to sink" if r["tier"] == 2 else "-"))
            if r["note"]:
                W("| **How it was proven** | {} |".format(_esc(r["note"])))
            if r["status"] == "fixed":
                W("| **What we did** | Fixed, and locked behind a regression test |")
                W("| **Guarded by** | `{}` |".format(r["fix_test"] or "-"))
            elif r["status"] == "regressed":
                W("| **What happened** | Was fixed, then the fix was removed |")
                W("| **Guarded by** | `{}` — this test is failing now |".format(r["fix_test"] or "-"))
            else:
                W("| **What we did** | Reported, not auto-fixed |")
            if r["snippet"]:
                label = ("The vulnerable code that was found and replaced:"
                         if r["status"] == "fixed" else "The vulnerable code:")
                W("\n{}\n".format(label))
                W("```\n{}\n```\n".format(r["snippet"][:300]))
            W("")

    # ---- honest limits ------------------------------------------------------
    W("---\n")
    W("## What this audit does **not** tell you\n")
    W("This is the most important section for anyone reading the grade above.\n")
    W("- **The grade covers what was examined, and nothing else.** A clean "
      "result on the classes checked says nothing about the ones that were not.")
    W("- **It cannot prove the absence of vulnerabilities.** \"No proven "
      "findings\" means nothing was demonstrated — not that nothing is there.")
    W("- **It is a code audit, not a penetration test.** Running "
      "infrastructure, network configuration, TLS setup, DNS, and cloud IAM "
      "were not touched.")
    W("- **Business-logic flaws need product knowledge.** A discount that can "
      "be applied twice, or a workflow step that can be skipped, is invisible "
      "without knowing the intended behaviour.")
    if not_checked:
        W("\n**Specifically not checked in this run:**\n")
        W(not_checked + "\n")
    W("")

    # ---- appendices ---------------------------------------------------------
    if unproven:
        W("---\n")
        W("## Appendix A — Unverified leads ({})\n".format(len(unproven)))
        W("Flagged, but **not** proven. These are deliberately not counted as "
          "vulnerabilities and do not affect the grade — reporting unproven "
          "leads as findings is how security tools train people to ignore them.\n")
        W("| Lead | Where | Severity | Flagged by |")
        W("|------|-------|----------|------------|")
        for r in unproven:
            W("| {} | `{}:{}` | {} | {} |".format(
                _esc(r["title"], 60), r["path"], r["line"],
                r["severity"], _esc(r["tool"] or "-", 40)))
        W("")

    if discarded:
        W("---\n")
        W("## Appendix B — Ruled out ({})\n".format(len(discarded)))
        W("Investigated and dismissed. The reason matters: it stops the next "
          "scan re-raising the same false positive.\n")
        W("| Candidate | Why it was ruled out |")
        W("|-----------|----------------------|")
        for r in discarded:
            W("| {} | {} |".format(_esc(r["title"], 50),
                                   _esc(r["note"] or "no reason recorded", 100)))
        W("")

    # ---- next steps ---------------------------------------------------------
    W("---\n")
    W("## Recommended next steps\n")
    n = 1
    if regressed:
        W("{}. **Restore the {} immediately** and find out why the guarding "
          "test did not block the change — a test that fails in CI but merges "
          "anyway is not protecting anything.".format(
              n, _n(len(regressed), "regressed fix", "regressed fixes")))
        n += 1
    open_now = [r for r in still_open if r["status"] != "regressed"]
    if open_now:
        W("{}. **Address the {} still open**, starting with the highest "
          "severity.".format(n, _n(len(open_now), "finding")))
        n += 1
    if unproven:
        W("{}. **Triage the {}** — either prove them or rule them out with a "
          "recorded reason.".format(n, _n(len(unproven), "unverified lead")))
        n += 1
    W("{}. **Run the regression tests in CI.** The fixes above are only "
      "permanent if something re-checks them on every commit.".format(n))
    n += 1
    W("{}. **Widen the scope.** This audit covered what is listed above; the "
      "classes it did not reach are still unknown.".format(n))
    W("\n---\n")
    W("<sub>Generated by [scanme](https://github.com/Adnaan5sal/scanme) — a security audit that "
      "only reports what it can prove. Findings are tracked in "
      "`.scanme/findings.db`, so a fix that silently reverts is caught on the "
      "next run.</sub>")
    return 0


# -- CLI ----------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(
        prog="findings.py",
        description="Persistent finding store for scanme.",
    )
    p.add_argument("--root", default=".", help="project root (default: cwd)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("ingest", help="load SARIF / npm-audit / native JSON")
    s.add_argument("file")
    s.add_argument("--label", help="what this run was, e.g. 'pre-launch'")
    s.add_argument("--no-close", action="store_true",
                   help="do not mark absent findings as 'gone' (for partial scans)")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("list", help="list findings")
    s.add_argument("--status",
                   help="candidate|proven|discarded|fixed|regressed|accepted|gone|open")
    s.add_argument("--severity", help="critical|high|medium|low|info")
    s.add_argument("--tier", type=int)
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("show", help="full detail + history for one finding")
    s.add_argument("fingerprint")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("promote", help="mark proven (Tier 1 or 2)")
    s.add_argument("fingerprint")
    s.add_argument("--tier", type=int, required=True, choices=[1, 2])
    s.add_argument("--note", help="how it was proven")
    s.set_defaults(func=cmd_promote)

    s = sub.add_parser("discard", help="rule out a candidate")
    s.add_argument("fingerprint")
    s.add_argument("--reason", required=True)
    s.set_defaults(func=cmd_discard)

    s = sub.add_parser("fix", help="mark fixed (requires a regression test)")
    s.add_argument("fingerprint")
    s.add_argument("--test", help="path to the regression test guarding it")
    s.add_argument("--commit")
    s.add_argument("--force", action="store_true", help="allow marking fixed with no test")
    s.set_defaults(func=cmd_fix)

    s = sub.add_parser("accept", help="formally accept the risk")
    s.add_argument("fingerprint")
    s.add_argument("--reason", required=True)
    s.add_argument("--owner", required=True)
    s.add_argument("--until", required=True, help="review date, YYYY-MM-DD")
    s.set_defaults(func=cmd_accept)

    sub.add_parser("diff", help="what changed since the previous run").set_defaults(func=cmd_diff)
    sub.add_parser("stats", help="counts by status and severity").set_defaults(func=cmd_stats)
    sub.add_parser("scorecard", help="before/after grade, at a glance").set_defaults(func=cmd_scorecard)
    sub.add_parser("report", help="full audit report in markdown").set_defaults(func=cmd_report)

    s = sub.add_parser("meta", help="record audit scope shown in the report")
    s.add_argument("key", help="scope | not_checked | project")
    s.add_argument("--set", dest="value", default=None)
    s.set_defaults(func=cmd_meta)
    return p


def main(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
