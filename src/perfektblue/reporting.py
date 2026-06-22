"""JSON and standalone HTML report generation."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def write_json_report(result: dict[str, Any], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(destination)
    return destination


def _finding_rows(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<tr><td colspan="4">No module findings were produced.</td></tr>'
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding['module_id']))}</td>"
            f"<td>{html.escape(str(finding['title']))}</td>"
            f'<td><span class="status">{html.escape(str(finding["status"]))}</span></td>'
            f"<td>{html.escape(str(finding['summary']))}</td>"
            "</tr>"
        )
    return "".join(rows)


def _module_rows(modules: list[dict[str, Any]]) -> str:
    rows = []
    for module in modules:
        selected = "selected" if module["selected"] else "skipped"
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(module['module_id']))}</td>"
            f"<td>{html.escape(str(module['risk']))}</td>"
            f"<td>{selected}</td>"
            f"<td>{html.escape(str(module['reason']))}</td>"
            "</tr>"
        )
    return "".join(rows)


def write_html_report(result: dict[str, Any], destination: Path) -> Path:
    target = result["target"]
    plan = result["plan"]
    verdict = html.escape(str(result["injection_verdict"]))
    reason = html.escape(str(result["verdict_reason"]))
    address = html.escape(str(target["address"]))
    name = html.escape(str(target.get("name") or "Unnamed device"))
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PerfektBlue assessment — {address}</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #0b1117;
  --panel: #121c25;
  --ink: #edf4f8;
  --muted: #9bb0bd;
  --accent: #65c4ce;
  --line: #263844;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.6 ui-sans-serif, system-ui, sans-serif;
}}
main {{ width: min(1120px, calc(100% - 40px)); margin: 64px auto 96px; }}
h1 {{ font-size: clamp(34px, 6vw, 68px); letter-spacing: -0.045em; line-height: 0.98; }}
h2 {{ margin-top: 48px; font-size: 22px; }}
.eyebrow {{ color: var(--accent); letter-spacing: .12em; text-transform: uppercase; }}
.summary {{ display: grid; grid-template-columns: 1.5fr 1fr; gap: 2px; margin-top: 36px; }}
.panel {{ background: var(--panel); padding: 28px; }}
.verdict {{ color: var(--accent); font-size: 28px; font-weight: 650; }}
.muted {{ color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; background: var(--panel); }}
th, td {{
  text-align: left;
  vertical-align: top;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
}}
th {{ color: var(--muted); font-size: 12px; letter-spacing: .08em; text-transform: uppercase; }}
.status {{ color: var(--accent); }}
code {{ color: var(--accent); }}
@media (max-width: 720px) {{
  .summary {{ grid-template-columns: 1fr; }}
  main {{ margin-top: 36px; }}
}}
</style>
</head>
<body>
<main>
<p class="eyebrow">PerfektBlue / Bluetooth assessment</p>
<h1>{name}<br><span class="muted">{address}</span></h1>
<section class="summary">
  <div class="panel">
    <div class="muted">Injection assessment</div>
    <div class="verdict">{verdict}</div>
    <p>{reason}</p>
  </div>
  <div class="panel">
    <div class="muted">Session</div>
    <p><code>{html.escape(str(result["session_id"]))}</code></p>
    <div class="muted">Completed</div>
    <p>{html.escape(str(result["completed_at"]))}</p>
  </div>
</section>
<h2>Executed plan</h2>
<table>
<thead><tr><th>Module</th><th>Risk</th><th>Decision</th><th>Reason</th></tr></thead>
<tbody>{_module_rows(plan["modules"])}</tbody>
</table>
<h2>Findings</h2>
<table>
<thead><tr><th>Module</th><th>Finding</th><th>Status</th><th>Summary</th></tr></thead>
<tbody>{_finding_rows(result["findings"])}</tbody>
</table>
<h2>Method limits</h2>
<p class="muted">A no-known-path, blocked, unsupported, or inconclusive result does not prove
that a device is immune to every unknown vulnerability. PerfektBlue reports only the paths and
evidence tested in this session.</p>
</main>
</body>
</html>
"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(document, encoding="utf-8")
    temporary.replace(destination)
    return destination
