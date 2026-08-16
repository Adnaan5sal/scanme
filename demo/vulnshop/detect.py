#!/usr/bin/env python
"""
detect.py - a minimal source detector for the two vulnerabilities in vulnshop.

This stands in for the scanner in the demo, and it exists for a specific
reason: Semgrep scans server.js with 225 rules and reports zero. Both real
vulnerabilities here are invisible to it -

  * the IDOR is semantic. No generic rule can know that `orders.user_id` is
    supposed to match the session user. Broken object-level authorization is
    the most common serious web vulnerability and essentially no static
    ruleset finds it.

  * the SQL injection sinks into `node:sqlite`'s DatabaseSync.prepare(), an
    API added in Node 22.5. Rulesets know mysql, pg, and sequelize. They do
    not know this one yet.

So the demo needs something that reports what is *actually* in the file right
now, rather than a fixed list. That distinction is the whole point of
regression detection: re-ingesting a static list would flag everything as
regressed whether or not it came back, which would be a lie.

    python detect.py server.js > found.json
"""

import json
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "server.js"

with open(SRC, encoding="utf-8") as fh:
    lines = fh.readlines()
source = "".join(lines)


def line_of(pattern):
    for i, line in enumerate(lines, 1):
        if re.search(pattern, line):
            return i, line.strip()
    return 0, ""


findings = []

# -- IDOR ---------------------------------------------------------------------
# Vulnerable when the orders lookup selects on id alone. Fixed when the query
# also constrains user_id, which is what makes another user's row not exist.
orders_q = re.search(
    r"prepare\(\s*['\"]SELECT \* FROM orders WHERE id = \?([^'\"]*)['\"]", source
)
if orders_q and "user_id" not in orders_q.group(1):
    ln, text = line_of(r"FROM orders WHERE id")
    findings.append(
        {
            "fingerprint": "idor4471orders0",
            "rule_id": "manual/idor-orders",
            "tool": "detect.py (semantic check semgrep has no rule for)",
            "path": SRC,
            "line": ln,
            "title": "IDOR: GET /api/orders/:id returns any user's order",
            "message": (
                "Authentication is enforced but authorization is not. The orders "
                "query selects on id alone, so any authenticated user can read any "
                "order, including card_last4."
            ),
            "snippet": text,
            "severity": "critical",
            "cwe": ["CWE-639"],
        }
    )

# -- SQL injection ------------------------------------------------------------
# Vulnerable when the products query is assembled by concatenation. Fixed when
# the statement is constant and the value is bound.
if re.search(r"FROM products WHERE name LIKE[^\n]*\+", source):
    ln, text = line_of(r"FROM products WHERE name LIKE[^\n]*\+")
    findings.append(
        {
            "fingerprint": "sqli0search0000",
            "rule_id": "manual/sqli-search",
            "tool": "detect.py (sink is node:sqlite, unknown to rulesets)",
            "path": SRC,
            "line": ln,
            "title": "SQL injection in GET /api/search",
            "message": (
                "Query assembled by string interpolation, so input is parsed as SQL "
                "rather than matched as data. A UNION payload reaches the users table."
            ),
            "snippet": text,
            "severity": "critical",
            "cwe": ["CWE-89"],
        }
    )

json.dump(findings, sys.stdout, indent=2)
sys.stdout.write("\n")
sys.stderr.write("detect.py: {} vulnerability(ies) present in {}\n".format(len(findings), SRC))
