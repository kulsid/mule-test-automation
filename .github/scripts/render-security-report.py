#!/usr/bin/env python3
"""
Merge the four security-scan outputs into a single self-contained HTML
report. Called by the security-consolidated-report job after all four
upstream artifacts have been downloaded.

Expected inputs (relative to REPO_ROOT):
  mulesoft-scan/security-report.json          (MuleSoft best practices)
  mulesoft-scan/security-report.md            (optional, embedded raw)
  gitleaks-scan/gitleaks-report.json          (Gitleaks findings)
  cyclonedx-scan/sbom.json                    (CycloneDX SBOM)
  osv-scan/osv-report.json                    (OSV findings)

Output: security-report.html  (single self-contained page).
"""
from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return {"__error__": f"{path.name}: invalid JSON — {e}"}


def h(s) -> str:
    return html.escape(str(s), quote=True)


# ---------- Section renderers ------------------------------------------- #

def render_mulesoft(data) -> tuple[str, str]:
    if data is None:
        return "MISSING", "<p class='muted'>MuleSoft security scan report not found.</p>"
    if "__error__" in data:
        return "ERROR", f"<p class='fail'>{h(data['__error__'])}</p>"
    passed = data.get("passed", 0)
    total = data.get("total", 0)
    pct = data.get("pass_percent", 0)
    threshold = data.get("threshold_percent", 80)
    ok = data.get("threshold_met", False)
    badge = "PASS" if ok else "FAIL"

    rows = []
    for c in data.get("checks", []):
        mark = "PASS" if c.get("passed") else "FAIL"
        cls = "pass" if c.get("passed") else "fail"
        rows.append(
            f"<tr><td>{h(c.get('id',''))}</td><td>{h(c.get('title',''))}</td>"
            f"<td class='{cls}'>{mark}</td><td>{h(c.get('detail',''))}</td></tr>"
        )

    body = f"""
      <p><strong>Pass rate:</strong> {passed}/{total} = <strong>{pct}%</strong>
         (threshold: {threshold}%)</p>
      <table>
        <thead><tr><th>ID</th><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>{''.join(rows) or '<tr><td colspan=4 class="muted">no checks reported</td></tr>'}</tbody>
      </table>
    """
    return badge, body


def render_gitleaks(data) -> tuple[str, str]:
    if data is None:
        return "MISSING", "<p class='muted'>Gitleaks report not found.</p>"
    if isinstance(data, dict) and "__error__" in data:
        return "ERROR", f"<p class='fail'>{h(data['__error__'])}</p>"
    if not isinstance(data, list):
        return "ERROR", "<p class='fail'>Unexpected Gitleaks output format.</p>"

    if not data:
        return "PASS", "<p class='pass'>No secrets detected. ✅</p>"

    rows = []
    for f in data:
        rows.append(
            "<tr>"
            f"<td>{h(f.get('RuleID',''))}</td>"
            f"<td>{h(f.get('File',''))}</td>"
            f"<td>{h(f.get('StartLine',''))}</td>"
            f"<td>{h(f.get('Description',''))}</td>"
            f"<td><code>{h((f.get('Secret') or '')[:80])}</code></td>"
            "</tr>"
        )
    body = f"""
      <p class='fail'><strong>{len(data)} secret(s) detected.</strong></p>
      <table>
        <thead><tr><th>Rule</th><th>File</th><th>Line</th><th>Description</th><th>Secret (redacted)</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    """
    return "FAIL", body


def render_sbom(data) -> tuple[str, str]:
    if data is None:
        return "MISSING", "<p class='muted'>CycloneDX SBOM not found.</p>"
    if isinstance(data, dict) and "__error__" in data:
        return "ERROR", f"<p class='fail'>{h(data['__error__'])}</p>"

    components = (data or {}).get("components") or []
    meta = ((data or {}).get("metadata") or {}).get("component") or {}

    rows = []
    for c in components:
        rows.append(
            "<tr>"
            f"<td>{h(c.get('group',''))}</td>"
            f"<td>{h(c.get('name',''))}</td>"
            f"<td>{h(c.get('version',''))}</td>"
            f"<td>{h(c.get('type',''))}</td>"
            f"<td><code>{h(c.get('purl',''))}</code></td>"
            "</tr>"
        )

    body = f"""
      <p><strong>Application:</strong> {h(meta.get('group',''))}/{h(meta.get('name',''))}
         version {h(meta.get('version',''))}</p>
      <p><strong>Total components:</strong> {len(components)}</p>
      <details><summary>Component list</summary>
        <table>
          <thead><tr><th>Group</th><th>Name</th><th>Version</th><th>Type</th><th>PURL</th></tr></thead>
          <tbody>{''.join(rows) or '<tr><td colspan=5 class="muted">no components</td></tr>'}</tbody>
        </table>
      </details>
    """
    # SBOM is informational — always OK unless the file was missing/bad.
    return "OK", body


def render_osv(data) -> tuple[str, str]:
    if data is None:
        return "MISSING", "<p class='muted'>OSV report not found.</p>"
    if isinstance(data, dict) and "__error__" in data:
        return "ERROR", f"<p class='fail'>{h(data['__error__'])}</p>"

    findings = []
    for result in (data or {}).get("results", []) or []:
        src = ((result.get("source") or {}).get("path")) or ""
        for pkg in result.get("packages", []) or []:
            pinfo = pkg.get("package") or {}
            for v in pkg.get("vulnerabilities", []) or []:
                # Best-effort severity extraction.
                sev_score = ""
                for sev in v.get("severity", []) or []:
                    if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
                        sev_score = sev.get("score", "")
                        break
                findings.append({
                    "package": f"{pinfo.get('name','')}@{pinfo.get('version','')}",
                    "ecosystem": pinfo.get("ecosystem", ""),
                    "source": src,
                    "id": v.get("id", ""),
                    "summary": v.get("summary", "") or v.get("details", "")[:200],
                    "severity": sev_score,
                    "aliases": ", ".join(v.get("aliases", []) or []),
                })

    if not findings:
        return "PASS", "<p class='pass'>No known vulnerabilities detected. ✅</p>"

    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{h(f['id'])}</td>"
            f"<td>{h(f['package'])}</td>"
            f"<td>{h(f['ecosystem'])}</td>"
            f"<td>{h(f['severity'])}</td>"
            f"<td>{h(f['summary'])}</td>"
            f"<td>{h(f['aliases'])}</td>"
            "</tr>"
        )
    body = f"""
      <p class='fail'><strong>{len(findings)} vulnerability finding(s).</strong></p>
      <table>
        <thead><tr><th>ID</th><th>Package</th><th>Ecosystem</th><th>Severity</th><th>Summary</th><th>Aliases</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    """
    return "FAIL", body


# ---------- Assemble ---------------------------------------------------- #

def badge_html(state: str) -> str:
    cls = {
        "PASS": "badge-pass",
        "OK": "badge-pass",
        "FAIL": "badge-fail",
        "ERROR": "badge-fail",
        "MISSING": "badge-warn",
    }.get(state, "badge-warn")
    return f"<span class='badge {cls}'>{h(state)}</span>"


def main() -> int:
    mulesoft_data  = read_json(REPO_ROOT / "mulesoft-scan"  / "security-report.json")
    gitleaks_data  = read_json(REPO_ROOT / "gitleaks-scan"  / "gitleaks-report.json")
    sbom_data      = read_json(REPO_ROOT / "cyclonedx-scan" / "sbom.json")
    osv_data       = read_json(REPO_ROOT / "osv-scan"       / "osv-report.json")

    ms_state,  ms_body  = render_mulesoft(mulesoft_data)
    gl_state,  gl_body  = render_gitleaks(gitleaks_data)
    sb_state,  sb_body  = render_sbom(sbom_data)
    osv_state, osv_body = render_osv(osv_data)

    run_url = os.environ.get("GITHUB_SERVER_URL", "") + "/" \
        + os.environ.get("GITHUB_REPOSITORY", "") + "/actions/runs/" \
        + os.environ.get("GITHUB_RUN_ID", "")
    sha = os.environ.get("GITHUB_SHA", "")
    ref = os.environ.get("GITHUB_REF_NAME", "")

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Report — {h(os.environ.get('GITHUB_REPOSITORY',''))}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem;
         line-height: 1.5; color: #222; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #1a1a1a; color: #ddd; }}
    table, th, td {{ border-color: #444 !important; }}
    th {{ background: #2a2a2a !important; }}
    code {{ background: #2a2a2a; }}
    a {{ color: #77aaff; }}
    details summary {{ color: #ddd; }}
  }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: .3em; }}
  h2 {{ margin-top: 2.5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0;
           font-size: 0.9rem; }}
  th, td {{ border: 1px solid #ccc; padding: .4rem .6rem; text-align: left;
            vertical-align: top; }}
  th {{ background: #f5f5f5; }}
  code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px;
          font-size: 0.85em; word-break: break-all; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px;
            font-size: .8rem; font-weight: 600; letter-spacing: .05em; }}
  .badge-pass {{ background: #1b7f37; color: white; }}
  .badge-fail {{ background: #c92a2a; color: white; }}
  .badge-warn {{ background: #b0741a; color: white; }}
  .pass {{ color: #1b7f37; }}
  .fail {{ color: #c92a2a; font-weight: 500; }}
  .muted {{ color: #666; font-style: italic; }}
  .summary-grid {{ display: grid;
                   grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                   gap: 1rem; margin: 1.5rem 0; }}
  .summary-card {{ border: 1px solid #ccc; border-radius: 8px; padding: 1rem;
                   background: rgba(0,0,0,0.02); }}
  .summary-card h3 {{ margin: 0 0 .3rem 0; font-size: 1rem; }}
  details {{ margin: .5rem 0; }}
  details summary {{ cursor: pointer; padding: .3rem 0; user-select: none; }}
</style>
</head>
<body>

<h1>Consolidated Security Report</h1>

<p class="muted">
  Repository: <code>{h(os.environ.get('GITHUB_REPOSITORY',''))}</code><br>
  Ref: <code>{h(ref)}</code> · Commit: <code>{h(sha[:12])}</code><br>
  Run: <a href="{h(run_url)}">{h(run_url)}</a>
</p>

<h2>Summary</h2>
<div class="summary-grid">
  <div class="summary-card">
    <h3>MuleSoft Best Practices</h3>
    {badge_html(ms_state)}
  </div>
  <div class="summary-card">
    <h3>Gitleaks Secrets Scan</h3>
    {badge_html(gl_state)}
  </div>
  <div class="summary-card">
    <h3>CycloneDX SBOM</h3>
    {badge_html(sb_state)}
  </div>
  <div class="summary-card">
    <h3>OSV Vulnerability Scan</h3>
    {badge_html(osv_state)}
  </div>
</div>

<h2>MuleSoft Security Best-Practices Scan</h2>
{ms_body}

<h2>Gitleaks Secret Scan</h2>
{gl_body}

<h2>CycloneDX SBOM</h2>
{sb_body}

<h2>OSV Vulnerability Scan</h2>
{osv_body}

</body>
</html>
"""
    out = REPO_ROOT / "security-report.html"
    out.write_text(html_doc, encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
