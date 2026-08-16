#!/usr/bin/env python
"""
authorize.py - the gate that must pass before any live-target testing runs.

Strix and every other dynamic tester carry this same rule under the hood:
testing a system you don't have clear permission for is not a thoroughness
win, it is a legal problem for the user. This script makes the check
mechanical instead of trusting the model to remember to ask every time -
Phase 0 of the workflow refuses to enter Phase 3 (live exploitation) without
a recorded authorization for the exact target.

Two scopes:

    owner        - the user has stated, in this session, that they own or
                   fully control the target (their own repo, their own
                   staging server). No further evidence required, but the
                   record still exists so it's auditable.

    third-party  - the user is testing something they don't own outright but
                   have permission for (a client engagement, a bug-bounty
                   program, a pentest contract). Requires a --note describing
                   the authorization (contract reference, bug-bounty program
                   name and scope URL, engagement letter) - a bare "yes" is
                   not enough for this tier, because "someone told me I could"
                   is exactly the failure mode this gate exists to prevent.

Storage: .scanme/authorization.json - one record per target, keyed by the
target string itself so re-running against the same target doesn't require
re-authorizing, but a new target always does.

    python authorize.py record --target https://staging.acme.test \\
        --scope owner --by "the user, this session"

    python authorize.py record --target https://acme.com \\
        --scope third-party --by "Acme Corp" \\
        --note "Bug bounty program, scope: *.acme.com, ref BB-2026-114"

    python authorize.py check --target https://acme.com
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

STORE_DIR = ".scanme"
STORE_NAME = "authorization.json"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def store_path(root):
    return Path(root) / STORE_DIR / STORE_NAME


def load(root):
    p = store_path(root)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save(root, data):
    p = store_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def cmd_record(args):
    if args.scope == "third-party" and not args.note:
        sys.stderr.write(
            "Third-party authorization requires --note describing the actual\n"
            "authorization (contract reference, bug-bounty program + scope URL,\n"
            "engagement letter). A bare confirmation is not sufficient at this\n"
            "tier - record what the authorization actually is.\n"
        )
        return 1

    data = load(args.root)
    data[args.target] = {
        "scope": args.scope,
        "by": args.by,
        "note": args.note or "",
        "recorded_at": now(),
    }
    save(args.root, data)
    print("Authorization recorded for {}".format(args.target))
    print("  scope: {}".format(args.scope))
    print("  by:    {}".format(args.by))
    if args.note:
        print("  note:  {}".format(args.note))
    return 0


def cmd_check(args):
    data = load(args.root)
    rec = data.get(args.target)
    if not rec:
        print("NOT AUTHORIZED: {}".format(args.target))
        print("No authorization record found. Live-target testing must not")
        print("proceed. Record one first:")
        print("  python authorize.py record --target {} --scope owner --by \"...\"".format(args.target))
        return 1

    print("AUTHORIZED: {}".format(args.target))
    print("  scope:      {}".format(rec["scope"]))
    print("  by:         {}".format(rec["by"]))
    print("  recorded:   {}".format(rec["recorded_at"]))
    if rec.get("note"):
        print("  note:       {}".format(rec["note"]))
    return 0


def cmd_list(args):
    data = load(args.root)
    if not data:
        print("No authorizations recorded.")
        return 0
    for target, rec in data.items():
        print("{}  [{}]  by {}  ({})".format(
            target, rec["scope"], rec["by"], rec["recorded_at"]))
    return 0


def cmd_revoke(args):
    data = load(args.root)
    if args.target not in data:
        print("No authorization for {} - nothing to revoke.".format(args.target))
        return 0
    del data[args.target]
    save(args.root, data)
    print("Authorization revoked for {}".format(args.target))
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="authorize.py")
    p.add_argument("--root", default=".")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("record", help="record authorization for a target")
    s.add_argument("--target", required=True)
    s.add_argument("--scope", required=True, choices=["owner", "third-party"])
    s.add_argument("--by", required=True, help="who confirmed this / who granted it")
    s.add_argument("--note", help="required for third-party: contract ref, bounty program, etc.")
    s.set_defaults(func=cmd_record)

    s = sub.add_parser("check", help="check whether a target is authorized")
    s.add_argument("--target", required=True)
    s.set_defaults(func=cmd_check)

    sub.add_parser("list", help="list all recorded authorizations").set_defaults(func=cmd_list)

    s = sub.add_parser("revoke", help="remove an authorization record")
    s.add_argument("--target", required=True)
    s.set_defaults(func=cmd_revoke)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
