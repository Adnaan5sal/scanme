#!/usr/bin/env python
"""
dashboard.py - a self-contained HTML dashboard rendered from the finding
store, the equivalent of Strix's live web viewer.

No server, no JS framework, no build step - one HTML file with inline CSS
and a small vanilla-JS filter, so it opens directly in a browser and can be
attached to a PR, emailed, or dropped in CI artifacts without any hosting.

    python dashboard.py --root . -o dashboard.html
    python dashboard.py --root . > dashboard.html
"""

import argparse
import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import connect, fetch, posture, get_meta, SEV_ORDER, now  # noqa: E402

STATUS_BADGE = {
    "proven": ("#d97706", "PROVEN"),
    "fixed": ("#16a34a", "FIXED"),
    "regressed": ("#dc2626", "REGRESSED"),
    "candidate": ("#6b7280", "CANDIDATE"),
    "discarded": ("#9ca3af", "DISCARDED"),
    "accepted": ("#0891b2", "ACCEPTED"),
    "gone": ("#9ca3af", "GONE"),
}
SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}


def e(text):
    return html.escape(str(text or ""), quote=True)


def render_row(r):
    color, label = STATUS_BADGE.get(r["status"], ("#6b7280", (r["status"] or "").upper()))
    sev = r["severity"] or "info"
    return """
    <tr class="row" data-status="{status}" data-sev="{sev}">
      <td><span class="dot" style="background:{sevcolor}"></span>{sev_label}</td>
      <td class="mono">{fp}</td>
      <td>{title}</td>
      <td class="mono">{path}:{line}</td>
      <td><span class="badge" style="background:{color}20;color:{color};border:1px solid {color}55">{label}</span></td>
      <td class="mono">{tier}</td>
      <td>{agent}</td>
    </tr>""".format(
        status=e(r["status"]), sev=e(sev), sevcolor=SEV_COLOR.get(sev, "#6b7280"),
        sev_label=e(sev.upper()), fp=e(r["fingerprint"][:8]), title=e(r["title"]),
        path=e(r["path"]), line=r["line"] or 0, color=color, label=label,
        tier="T{}".format(r["tier"]) if r["tier"] else "-",
        agent=e(r["tool"] or "-"),
    )


def build(root):
    conn = connect(root, create=False)
    p = posture(conn)
    project = get_meta(conn, "project", Path(root).resolve().name)
    scope = get_meta(conn, "scope", "")

    all_rows = conn.execute("SELECT * FROM findings ORDER BY updated_at DESC").fetchall()
    all_rows = sorted(all_rows, key=lambda r: SEV_ORDER.get(r["severity"], 9))

    events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 40").fetchall()

    bg, bmeaning = p["before_grade"]
    ag, ameaning = p["after_grade"]
    regressed = [r for r in p["open"] if r["status"] == "regressed"]

    rows_html = "\n".join(render_row(r) for r in all_rows) or (
        '<tr><td colspan="7" style="text-align:center;color:#9ca3af;padding:24px">'
        "No findings recorded yet.</td></tr>"
    )

    activity_html = "\n".join(
        '<li><span class="mono" style="color:#9ca3af">{at}</span> '
        '<span class="badge-sm">{event}</span> '
        '<span class="mono">{fp}</span> {detail}</li>'.format(
            at=e(ev["at"]), event=e(ev["event"]), fp=e(ev["fingerprint"][:8]),
            detail=e(ev["detail"] or ""),
        )
        for ev in events
    ) or "<li>No activity yet.</li>"

    banner = ""
    if regressed:
        banner = ('<div class="warn">&#9888; {} regressed finding(s) - a fix '
                   'that was verified previously has come back.</div>').format(len(regressed))

    return TEMPLATE.format(
        project=e(project),
        generated=e(now()),
        scope=e(scope) or "Not recorded",
        regressed_banner=banner,
        before_score=p["before"], before_grade=bg, before_meaning=e(bmeaning),
        after_score=p["after"], after_grade=ag, after_meaning=e(ameaning),
        proven=len(p["ever"]), fixed=len(fetch(conn, "fixed")),
        open_count=len(p["open"]), regressed_count=len(regressed),
        rows=rows_html, activity=activity_html,
    )


TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>scanme — {project}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    font: 14px/1.5 -apple-system, "Segoe UI", sans-serif;
    background: #0b0f14; color: #e5e7eb; margin: 0; padding: 32px;
  }}
  .mono {{ font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12px; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .sub {{ color: #9ca3af; font-size: 12px; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{
    background: #131a22; border: 1px solid #232d38; border-radius: 10px;
    padding: 16px 20px; min-width: 140px;
  }}
  .card .label {{ color: #9ca3af; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }}
  .card .value {{ font-size: 26px; font-weight: 700; margin-top: 4px; }}
  .grade-flow {{ display: flex; align-items: center; gap: 20px; }}
  .grade-box {{ text-align: center; }}
  .grade-box .letter {{ font-size: 34px; font-weight: 800; }}
  .grade-box .score {{ color: #9ca3af; font-size: 12px; }}
  .arrow {{ color: #6b7280; font-size: 20px; }}
  table {{ width: 100%; border-collapse: collapse; background: #131a22;
    border: 1px solid #232d38; border-radius: 10px; overflow: hidden; }}
  th {{ text-align: left; padding: 10px 12px; background: #1a2129; color: #9ca3af;
    font-size: 11px; text-transform: uppercase; letter-spacing: .04em; border-bottom: 1px solid #232d38; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1a2129; }}
  tr.row:hover {{ background: #171f28; }}
  .dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }}
  .badge {{ padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
  .badge-sm {{ background: #1a2129; padding: 1px 6px; border-radius: 4px; font-size: 10px; }}
  .filters {{ margin: 16px 0; display: flex; gap: 8px; }}
  .filters button {{
    background: #131a22; border: 1px solid #232d38; color: #e5e7eb;
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;
  }}
  .filters button.active {{ background: #2563eb; border-color: #2563eb; }}
  .panel {{ background: #131a22; border: 1px solid #232d38; border-radius: 10px; padding: 16px 20px; margin-top: 24px; }}
  .panel h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: #9ca3af; margin: 0 0 12px; }}
  .activity-list {{ list-style: none; margin: 0; padding: 0; max-height: 260px; overflow-y: auto; }}
  .activity-list li {{ padding: 6px 0; border-bottom: 1px solid #1a2129; font-size: 12px; }}
  .warn {{ background: #2a1215; border: 1px solid #7f1d1d; color: #fca5a5; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }}
</style></head>
<body>
  <h1>scanme — {project}</h1>
  <div class="sub">Generated {generated} · scope: {scope}</div>

  {regressed_banner}

  <div class="cards">
    <div class="card">
      <div class="label">Grade</div>
      <div class="grade-flow">
        <div class="grade-box"><div class="letter">{before_grade}</div><div class="score">{before_score}/100</div></div>
        <div class="arrow">&rarr;</div>
        <div class="grade-box"><div class="letter">{after_grade}</div><div class="score">{after_score}/100</div></div>
      </div>
    </div>
    <div class="card"><div class="label">Proven</div><div class="value">{proven}</div></div>
    <div class="card"><div class="label">Fixed</div><div class="value">{fixed}</div></div>
    <div class="card"><div class="label">Open</div><div class="value">{open_count}</div></div>
    <div class="card"><div class="label">Regressed</div><div class="value" style="color:#dc2626">{regressed_count}</div></div>
  </div>

  <div class="filters">
    <button class="active" onclick="filterSev('all',this)">All</button>
    <button onclick="filterSev('critical',this)">Critical</button>
    <button onclick="filterSev('high',this)">High</button>
    <button onclick="filterSev('medium',this)">Medium</button>
    <button onclick="filterSev('low',this)">Low</button>
  </div>

  <table>
    <thead><tr><th>Severity</th><th>ID</th><th>Finding</th><th>Location</th><th>Status</th><th>Tier</th><th>Source / agent</th></tr></thead>
    <tbody id="rows">{rows}</tbody>
  </table>

  <div class="panel">
    <h2>Recent activity</h2>
    <ul class="activity-list">{activity}</ul>
  </div>

  <script>
    function filterSev(sev, btn) {{
      document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('#rows tr.row').forEach(row => {{
        row.style.display = (sev === 'all' || row.dataset.sev === sev) ? '' : 'none';
      }});
    }}
  </script>
</body></html>
"""


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument("--root", default=".")
    p.add_argument("-o", "--output")
    args = p.parse_args(argv)

    html_out = build(args.root)

    if args.output:
        Path(args.output).write_text(html_out, encoding="utf-8")
        print("Dashboard written to {}".format(args.output))
    else:
        sys.stdout.write(html_out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
