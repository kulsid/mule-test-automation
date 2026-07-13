#!/usr/bin/env python3
"""
Merge all pipeline outputs into a single self-contained HTML report.
Called by the consolidated-report job after every upstream job's
intermediate artifact has been downloaded.

Expected inputs (relative to REPO_ROOT):
  munit-scan/munit-summary.json               (MUnit tests + coverage)
  mulesoft-scan/security-report.json          (MuleSoft best practices)
  gitleaks-scan/gitleaks-report.json          (Gitleaks findings)
  gitleaks-scan/gitleaks-run.log              (banner + INF summary lines)
  cyclonedx-scan/sbom.json                    (CycloneDX SBOM)
  osv-scan/osv-report.json                    (OSV findings)
  sonar-scan/measures.json                    (SonarQube — /api/measures)
  sonar-scan/issues.json                      (SonarQube — /api/issues/search)
  sonar-scan/hotspots.json                    (SonarQube — /api/hotspots/search)
  sonar-scan/sonar-report.html                (SonarQube — optional link)
  newman-scan/newman.json                     (Newman full JSON export)
  newman-scan/junit.xml                       (Newman JUnit — fallback)
  jmeter-scan/results.jtl                     (JMeter perf samples)

Output: consolidated-ci-report.html  (single self-contained page).
"""
from __future__ import annotations

import csv
import html
import json
import math
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------- Utilities --------------------------------------------------- #

def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return {"__error__": f"{path.name}: invalid JSON — {e}"}


def h(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def pct(n: int, d: int) -> str:
    return f"{(n/d)*100:.1f}%" if d else "n/a"


# ---------- Section renderers ------------------------------------------ #

def render_munit(data) -> tuple[str, str]:
    if data is None:
        return "MISSING", "<p class='muted'>MUnit summary not found.</p>"
    if isinstance(data, dict) and "__error__" in data:
        return "ERROR", f"<p class='fail'>{h(data['__error__'])}</p>"

    tests    = data.get("tests")
    errors   = data.get("errors")   or 0
    failures = data.get("failures") or 0
    skipped  = data.get("skipped")  or 0
    cov      = data.get("coverage")   or {}
    thr      = data.get("thresholds") or {}
    js       = (data.get("job_status") or "").lower()

    def cov_pass(k):
        v, t = cov.get(k), thr.get(k)
        return v is None or t is None or v >= t

    cov_ok = all(cov_pass(k) for k in ("application", "resource", "flow"))
    state = "PASS" if (js == "success" and errors == 0 and failures == 0 and cov_ok) else "FAIL"

    def cov_row(label, key):
        v = cov.get(key); t = thr.get(key)
        cls = "pass" if cov_pass(key) else "fail"
        v_disp = "n/a" if v is None else f"{v:.1f}%"
        t_disp = "—"   if t is None else f"≥ {t}%"
        gap    = "" if (v is None or t is None) else f" ({v-t:+.1f}%)"
        return f"<tr><td>{label}</td><td class='{cls}'>{v_disp}{gap}</td><td>{t_disp}</td></tr>"

    return state, f"""
      <p><strong>Job status:</strong> {h(js or 'unknown')}</p>
      <table>
        <thead><tr><th colspan="3">Tests</th></tr></thead>
        <tbody>
          <tr><td>Total</td><td colspan="2">{h(tests if tests is not None else 'n/a')}</td></tr>
          <tr><td>Failures</td><td colspan="2" class="{'fail' if failures else 'pass'}">{failures}</td></tr>
          <tr><td>Errors</td><td colspan="2" class="{'fail' if errors else 'pass'}">{errors}</td></tr>
          <tr><td>Skipped</td><td colspan="2">{skipped}</td></tr>
        </tbody>
      </table>
      <table>
        <thead><tr><th>Coverage dimension</th><th>Value</th><th>Threshold</th></tr></thead>
        <tbody>
          {cov_row('Application', 'application')}
          {cov_row('Resource',    'resource')}
          {cov_row('Flow',        'flow')}
        </tbody>
      </table>
      <p class="muted">Full interactive MUnit HTML report is published as
      the <code>detailed-munit-report</code> artifact on this run.</p>
    """


def render_newman(json_path: Path, xml_path: Path) -> tuple[str, str]:
    # Prefer the JSON export — it has request URLs, timings, and every
    # assertion (including the passing ones). Fall back to the JUnit XML
    # if JSON is unavailable.
    if json_path.exists():
        return _render_newman_json(read_json(json_path))
    return _render_newman_junit(xml_path)


def _render_newman_json(data) -> tuple[str, str]:
    if data is None:
        return "MISSING", "<p class='muted'>Newman JSON report not found.</p>"
    if isinstance(data, dict) and "__error__" in data:
        return "ERROR", f"<p class='fail'>{h(data['__error__'])}</p>"

    run = (data or {}).get("run", {}) or {}
    stats = run.get("stats", {}) or {}
    executions = run.get("executions", []) or []
    fail_records = run.get("failures", []) or []
    coll_name = (data.get("collection") or {}).get("info", {}).get("name", "")

    # ---- Overall stats table ----
    def stat_row(label, block):
        block = block or {}
        total = block.get("total", 0)
        failed = block.get("failed", 0)
        cls = "fail" if failed else "pass"
        return f"<tr><td>{label}</td><td>{total}</td><td class='{cls}'>{failed}</td></tr>"

    stats_html = "".join([
        stat_row("Requests",   stats.get("requests")),
        stat_row("Assertions", stats.get("assertions")),
        stat_row("Iterations", stats.get("iterations")),
        stat_row("Test Scripts", stats.get("testScripts")),
        stat_row("Pre-request Scripts", stats.get("prerequestScripts")),
    ])

    # ---- Per-request detail (URL, method, status, time, assertions) ----
    request_rows = []
    for i, ex in enumerate(executions, 1):
        item = ex.get("item", {}) or {}
        req  = ex.get("request", {}) or {}
        resp = ex.get("response") or {}
        url_obj = req.get("url") or {}
        url = url_obj.get("raw") or ""
        if not url and isinstance(url_obj, dict):
            host = ".".join(url_obj.get("host", []) or [])
            path = "/".join(url_obj.get("path", []) or [])
            url = f"{host}/{path}" if host else path
        method = req.get("method", "")
        status = resp.get("code", "—") if resp else "—"
        status_txt = resp.get("status", "") if resp else ""
        time_ms = resp.get("responseTime", "") if resp else ""
        size = (resp.get("responseSize", "") if resp else "") or ""

        # Per-request assertions
        assertions = ex.get("assertions", []) or []
        asserted_rows = []
        for a in assertions:
            ok = a.get("error") is None
            cls = "pass" if ok else "fail"
            name = a.get("assertion", "")
            err_msg = ""
            if not ok:
                err = a.get("error", {}) or {}
                err_msg = err.get("message") or err.get("name") or ""
            asserted_rows.append(
                f"<tr><td class='{cls}'>{'PASS' if ok else 'FAIL'}</td>"
                f"<td>{h(name)}</td>"
                f"<td class='fail'>{h(err_msg[:400])}</td></tr>"
            )

        assertions_block = ""
        if asserted_rows:
            assertions_block = (
                "<table class='inner'>"
                "<thead><tr><th>Result</th><th>Assertion</th><th>Error (if any)</th></tr></thead>"
                f"<tbody>{''.join(asserted_rows)}</tbody></table>"
            )

        row_status_cls = "pass" if (isinstance(status, int) and 200 <= status < 400) else "fail" if isinstance(status, int) else "muted"

        request_rows.append(f"""
          <tr>
            <td>#{i}</td>
            <td><strong>{h(item.get('name',''))}</strong></td>
            <td><code>{h(method)}</code></td>
            <td class='{row_status_cls}'>{h(status)} {h(status_txt)}</td>
            <td>{h(time_ms)}{"" if time_ms == "" else " ms"}</td>
            <td>{h(size)}</td>
          </tr>
          <tr><td colspan="6"><code>{h(url)}</code>{assertions_block}</td></tr>
        """)

    # State: any failure in the summary or in the executions
    total_failed = ((stats.get("assertions") or {}).get("failed", 0)
                    + (stats.get("requests")   or {}).get("failed", 0)
                    + len(fail_records))
    state = "PASS" if total_failed == 0 and executions else \
            "FAIL" if executions else "MISSING"

    body = f"""
      <p><strong>Collection:</strong> {h(coll_name)}</p>
      <p class="muted">Full interactive Newman HTML report is published as
      the <code>detailed-integration-report</code> artifact on this run.</p>
      <table>
        <thead><tr><th>Category</th><th>Total</th><th>Failed</th></tr></thead>
        <tbody>{stats_html}</tbody>
      </table>
      <h3 class="subsection">Requests</h3>
      <table>
        <thead>
          <tr>
            <th>#</th><th>Name</th><th>Method</th><th>Status</th>
            <th>Time</th><th>Size</th>
          </tr>
        </thead>
        <tbody>{''.join(request_rows) or '<tr><td colspan=6 class="muted">no executions recorded</td></tr>'}</tbody>
      </table>
    """
    return state, body


def _render_newman_junit(xml_path: Path) -> tuple[str, str]:
    if not xml_path.exists():
        return "MISSING", "<p class='muted'>Newman report not found.</p>"
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        return "ERROR", f"<p class='fail'>Newman JUnit parse error: {h(e)}</p>"

    tests = failures = errors = 0
    fail_rows = []
    for ts in root.iter("testsuite"):
        tests    += int(ts.get("tests")    or 0)
        failures += int(ts.get("failures") or 0)
        errors   += int(ts.get("errors")   or 0)
        for tc in ts.iter("testcase"):
            fail = tc.find("failure")
            err  = tc.find("error")
            if fail is not None or err is not None:
                node = fail if fail is not None else err
                fail_rows.append(
                    f"<tr><td>{h(ts.get('name',''))}</td>"
                    f"<td>{h(tc.get('name',''))}</td>"
                    f"<td class='fail'>{h((node.get('message') or '')[:400])}</td></tr>"
                )

    state = "PASS" if (tests > 0 and failures == 0 and errors == 0) else \
            "FAIL" if tests > 0 else "MISSING"

    body = f"""
      <p class="muted">JSON export unavailable; showing JUnit summary only.</p>
      <table>
        <tbody>
          <tr><td>Total assertions</td><td>{tests}</td></tr>
          <tr><td>Failures</td><td class="{'fail' if failures else 'pass'}">{failures}</td></tr>
          <tr><td>Errors</td><td class="{'fail' if errors else 'pass'}">{errors}</td></tr>
        </tbody>
      </table>
    """
    if fail_rows:
        body += f"""
          <table>
            <thead><tr><th>Suite</th><th>Assertion</th><th>Message</th></tr></thead>
            <tbody>{''.join(fail_rows)}</tbody>
          </table>
        """
    return state, body


def render_jmeter(jtl_path: Path) -> tuple[str, str]:
    if not jtl_path.exists():
        return "MISSING", "<p class='muted'>JMeter JTL not found.</p>"
    try:
        rows = list(csv.DictReader(jtl_path.open()))
    except Exception as e:
        return "ERROR", f"<p class='fail'>JMeter JTL parse error: {h(e)}</p>"

    if not rows:
        return "MISSING", "<p class='muted'>JMeter JTL is empty.</p>"

    # Percentile helper (nearest-rank)
    def pctile(sorted_list, p):
        if not sorted_list:
            return 0
        k = max(0, min(len(sorted_list) - 1, math.ceil(p / 100 * len(sorted_list)) - 1))
        return sorted_list[k]

    groups = defaultdict(list)
    for r in rows:
        groups[r.get("label", "unknown")].append(r)

    per_label = []
    total_fail = 0
    total_samples = 0
    for label, samples in groups.items():
        elapsed = sorted(int(s.get("elapsed") or 0) for s in samples)
        n = len(elapsed)
        total_samples += n
        fails = sum(1 for s in samples if s.get("success", "").lower() != "true")
        total_fail += fails
        mean = sum(elapsed) / n if n else 0
        # Distinct HTTP response codes seen for this sample
        codes = sorted({(s.get("responseCode") or "").strip() for s in samples if s.get("responseCode")})
        per_label.append({
            "label": label,
            "count": n,
            "fails": fails,
            "mean": mean,
            "min":  elapsed[0]  if elapsed else 0,
            "max":  elapsed[-1] if elapsed else 0,
            "p50":  pctile(elapsed, 50),
            "p90":  pctile(elapsed, 90),
            "p95":  pctile(elapsed, 95),
            "p99":  pctile(elapsed, 99),
            "codes": ", ".join(codes) or "—",
        })

    state = "PASS" if total_fail == 0 else "FAIL"

    rows_html = "".join(
        f"<tr>"
        f"<td><code>{h(r['label'])}</code></td>"
        f"<td>{r['count']}</td>"
        f"<td class='{'fail' if r['fails'] else 'pass'}'>{r['fails']}</td>"
        f"<td>{r['mean']:.0f}</td>"
        f"<td>{r['min']}</td>"
        f"<td>{r['p50']}</td>"
        f"<td>{r['p90']}</td>"
        f"<td>{r['p95']}</td>"
        f"<td>{r['p99']}</td>"
        f"<td>{r['max']}</td>"
        f"<td><code>{h(r['codes'])}</code></td>"
        f"</tr>"
        for r in per_label
    )

    # Also render a table of the FIRST 200 individual samples so the raw
    # data is available for inspection without needing the JTL file.
    sample_rows = []
    for r in rows[:200]:
        ok = (r.get("success", "").lower() == "true")
        sample_rows.append(
            f"<tr>"
            f"<td>{h(r.get('label',''))}</td>"
            f"<td>{h(r.get('elapsed',''))}</td>"
            f"<td>{h(r.get('responseCode',''))}</td>"
            f"<td class='{'pass' if ok else 'fail'}'>{'ok' if ok else 'fail'}</td>"
            f"<td>{h(r.get('threadName',''))}</td>"
            f"</tr>"
        )
    trimmed_note = "" if len(rows) <= 200 else f"<p class='muted'>Showing first 200 of {len(rows)} samples.</p>"

    return state, f"""
      <p><strong>Total samples:</strong> {total_samples} across {len(per_label)} distinct request(s)</p>
      <table>
        <thead>
          <tr>
            <th>Sample</th><th>Count</th><th>Failed</th>
            <th>Mean</th><th>Min</th><th>p50</th><th>p90</th><th>p95</th><th>p99</th><th>Max</th>
            <th>HTTP codes</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
      <p class="muted">All latency values in milliseconds.</p>
      <details>
        <summary>Raw per-sample table (first 200 rows)</summary>
        {trimmed_note}
        <table>
          <thead><tr><th>Label</th><th>Elapsed (ms)</th><th>HTTP</th><th>Result</th><th>Thread</th></tr></thead>
          <tbody>{''.join(sample_rows)}</tbody>
        </table>
      </details>
      <p class="muted">Full JMeter HTML dashboard is published as the
      <code>detailed-performance-report</code> artifact on this run.</p>
    """


def render_mulesoft(data) -> tuple[str, str]:
    if data is None:
        return "MISSING", "<p class='muted'>MuleSoft security scan report not found.</p>"
    if isinstance(data, dict) and "__error__" in data:
        return "ERROR", f"<p class='fail'>{h(data['__error__'])}</p>"
    passed = data.get("passed", 0)
    total  = data.get("total", 0)
    pctv   = data.get("pass_percent", 0)
    threshold = data.get("threshold_percent", 80)
    ok = data.get("threshold_met", False)
    state = "PASS" if ok else "FAIL"

    rows = []
    for c in data.get("checks", []):
        mark = "PASS" if c.get("passed") else "FAIL"
        cls  = "pass" if c.get("passed") else "fail"
        rows.append(
            f"<tr><td><code>{h(c.get('id',''))}</code></td><td>{h(c.get('title',''))}</td>"
            f"<td class='{cls}'>{mark}</td><td>{h(c.get('detail',''))}</td></tr>"
        )

    return state, f"""
      <p><strong>Pass rate:</strong> {passed}/{total} = <strong>{pctv}%</strong>
         (threshold: {threshold}%)</p>
      <table>
        <thead><tr><th>ID</th><th>Check</th><th>Result</th><th>Detail</th></tr></thead>
        <tbody>{''.join(rows) or '<tr><td colspan=4 class="muted">no checks reported</td></tr>'}</tbody>
      </table>
      <p class="muted">Reference:
        <a href="https://docs.mulesoft.com/general/security-best-practices">
          MuleSoft security best practices
        </a>
      </p>
    """


GITLEAKS_BANNER = r"""    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks"""


def render_gitleaks(data) -> tuple[str, str]:
    log_path = REPO_ROOT / "gitleaks-scan" / "gitleaks-run.log"
    log_lines = ""
    if log_path.exists():
        raw = log_path.read_text(errors="replace")
        keep = [ln for ln in raw.splitlines()
                if re.search(r'\b(INF|WRN|ERR)\b', ln)]
        log_lines = "\n".join(keep[:30])
    banner_block = (
        f"<pre class='banner'>{h(GITLEAKS_BANNER)}\n\n{h(log_lines)}</pre>"
        if log_lines else
        f"<pre class='banner'>{h(GITLEAKS_BANNER)}</pre>"
    )

    if data is None:
        return "MISSING", banner_block + "<p class='muted'>Gitleaks report not found.</p>"
    if isinstance(data, dict) and "__error__" in data:
        return "ERROR", banner_block + f"<p class='fail'>{h(data['__error__'])}</p>"
    if not isinstance(data, list):
        return "ERROR", banner_block + "<p class='fail'>Unexpected Gitleaks output format.</p>"
    if not data:
        return "PASS", banner_block + "<p class='pass'>No secrets detected.</p>"

    rows = []
    for f in data:
        rows.append(
            "<tr>"
            f"<td>{h(f.get('RuleID',''))}</td>"
            f"<td>{h(f.get('File',''))}</td>"
            f"<td>{h(f.get('StartLine',''))}</td>"
            f"<td>{h(f.get('Description',''))}</td>"
            f"<td>{h(f.get('Author', '') or '')}</td>"
            f"<td><code>{h((f.get('Commit') or '')[:12])}</code></td>"
            f"<td><code>{h((f.get('Secret') or '')[:80])}</code></td>"
            "</tr>"
        )
    body = banner_block + f"""
      <p class='fail'><strong>{len(data)} secret(s) detected.</strong></p>
      <table>
        <thead>
          <tr>
            <th>Rule</th><th>File</th><th>Line</th><th>Description</th>
            <th>Author</th><th>Commit</th><th>Secret (redacted)</th>
          </tr>
        </thead>
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
    tools = ((data or {}).get("metadata") or {}).get("tools") or []
    tool_names = ", ".join(f"{(t.get('vendor') or '') } {(t.get('name') or '')} {(t.get('version') or '')}".strip()
                           for t in tools if isinstance(t, dict))

    rows = []
    for c in components:
        licenses = c.get("licenses") or []
        lic_names = []
        for lic in licenses:
            lic_obj = (lic or {}).get("license") or {}
            lic_names.append(lic_obj.get("id") or lic_obj.get("name") or "")
        rows.append(
            "<tr>"
            f"<td>{h(c.get('group',''))}</td>"
            f"<td>{h(c.get('name',''))}</td>"
            f"<td>{h(c.get('version',''))}</td>"
            f"<td>{h(c.get('type',''))}</td>"
            f"<td>{h(', '.join([l for l in lic_names if l]))}</td>"
            f"<td><code>{h(c.get('purl',''))}</code></td>"
            "</tr>"
        )

    return "OK", f"""
      <p><strong>Application:</strong>
         {h(meta.get('group',''))}/{h(meta.get('name',''))}
         version {h(meta.get('version',''))}</p>
      <p><strong>Tooling:</strong> {h(tool_names) or '<span class="muted">unknown</span>'}</p>
      <details>
        <summary><strong>Component list</strong> ({len(components)} components — click to expand)</summary>
        <table>
          <thead>
            <tr>
              <th>Group</th><th>Name</th><th>Version</th><th>Type</th>
              <th>License(s)</th><th>PURL</th>
            </tr>
          </thead>
          <tbody>{''.join(rows) or '<tr><td colspan=6 class="muted">no components</td></tr>'}</tbody>
        </table>
      </details>
    """


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
                sev_score = sev_type = ""
                for sev in v.get("severity", []) or []:
                    sev_type  = sev.get("type", "")
                    sev_score = sev.get("score", "")
                    break
                findings.append({
                    "package":   f"{pinfo.get('name','')}@{pinfo.get('version','')}",
                    "ecosystem": pinfo.get("ecosystem", ""),
                    "source":    src,
                    "id":        v.get("id", ""),
                    "summary":   v.get("summary", "") or (v.get("details","") or "")[:400],
                    "sev_type":  sev_type,
                    "sev_score": sev_score,
                    "aliases":   ", ".join(v.get("aliases", []) or []),
                    "details":   v.get("details", "") or "",
                })

    if not findings:
        return "PASS", "<p class='pass'>No known vulnerabilities detected.</p>"

    rows = []
    for f in findings:
        details_block = (
            f"<details><summary>details</summary><pre>{h(f['details'])}</pre></details>"
            if f.get("details") else ""
        )
        rows.append(
            "<tr>"
            f"<td>{h(f['id'])}</td>"
            f"<td>{h(f['package'])}</td>"
            f"<td>{h(f['ecosystem'])}</td>"
            f"<td>{h(f['sev_type'])}: {h(f['sev_score'])}</td>"
            f"<td>{h(f['summary'])}{details_block}</td>"
            f"<td>{h(f['aliases'])}</td>"
            "</tr>"
        )
    return "FAIL", f"""
      <p class='fail'><strong>{len(findings)} vulnerability finding(s).</strong></p>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Package</th><th>Ecosystem</th><th>Severity</th>
            <th>Summary</th><th>Aliases</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    """


def render_sonar() -> tuple[str, str]:
    # Read the three API dumps written by the sonar-scan job.
    m_path = REPO_ROOT / "sonar-scan" / "measures.json"
    i_path = REPO_ROOT / "sonar-scan" / "issues.json"
    h_path = REPO_ROOT / "sonar-scan" / "hotspots.json"

    if not any(p.exists() for p in (m_path, i_path, h_path)):
        return "MISSING", "<p class='muted'>SonarQube API dumps not found.</p>"

    measures_data = read_json(m_path) or {}
    issues_data   = read_json(i_path) or {}
    hotspots_data = read_json(h_path) or {}

    measures_map = {}
    comp = (measures_data or {}).get("component") or {}
    for m in comp.get("measures", []) or []:
        measures_map[m.get("metric", "")] = m.get("value", "")

    measure_rows = "".join(
        f"<tr><td><code>{h(k)}</code></td><td>{h(v)}</td></tr>"
        for k, v in sorted(measures_map.items())
    ) or "<tr><td colspan=2 class='muted'>no measures</td></tr>"

    issues = issues_data.get("issues", []) or []
    issue_rows = "".join(
        f"<tr>"
        f"<td>{h(i.get('severity',''))}</td>"
        f"<td>{h(i.get('type',''))}</td>"
        f"<td><code>{h(i.get('rule',''))}</code></td>"
        f"<td>{h((i.get('component') or '').split(':')[-1])}:"
        f"{h((i.get('textRange') or {}).get('startLine',''))}</td>"
        f"<td>{h(i.get('message',''))}</td>"
        f"</tr>"
        for i in issues
    ) or "<tr><td colspan=5 class='muted'>no issues</td></tr>"

    hotspots = hotspots_data.get("hotspots", []) or []
    hotspot_rows = "".join(
        f"<tr>"
        f"<td>{h(hs.get('vulnerabilityProbability',''))}</td>"
        f"<td>{h(hs.get('securityCategory',''))}</td>"
        f"<td>{h((hs.get('component') or '').split(':')[-1])}:{h(hs.get('line',''))}</td>"
        f"<td>{h(hs.get('message',''))}</td>"
        f"</tr>"
        for hs in hotspots
    ) or "<tr><td colspan=4 class='muted'>no hotspots</td></tr>"

    # Determine state.
    def as_int(k):
        try: return int(measures_map.get(k, 0) or 0)
        except ValueError: return 0
    bugs = as_int("bugs"); vulns = as_int("vulnerabilities"); smells = as_int("code_smells")
    state = "PASS" if (bugs == 0 and vulns == 0 and len(issues) == 0) else "FAIL" if issues else "OK"

    # Optional link to the sonar-report HTML if it exists.
    html_link = ""
    if (REPO_ROOT / "sonar-scan" / "sonar-report.html").exists():
        html_link = ("<p class='muted'>Full interactive SonarQube HTML export is "
                     "published as the <code>detailed-sonar-report</code> "
                     "artifact on this run.</p>")

    body = f"""
      <h3 class="subsection">Measures</h3>
      <table>
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>{measure_rows}</tbody>
      </table>
      <h3 class="subsection">Issues ({len(issues)})</h3>
      <table>
        <thead>
          <tr>
            <th>Severity</th><th>Type</th><th>Rule</th>
            <th>Location</th><th>Message</th>
          </tr>
        </thead>
        <tbody>{issue_rows}</tbody>
      </table>
      <h3 class="subsection">Security Hotspots ({len(hotspots)})</h3>
      <table>
        <thead>
          <tr>
            <th>Probability</th><th>Category</th><th>Location</th><th>Message</th>
          </tr>
        </thead>
        <tbody>{hotspot_rows}</tbody>
      </table>
      {html_link}
    """
    return state, body


# ---------- Assemble ---------------------------------------------------- #

def badge_html(state: str) -> str:
    cls = {
        "PASS": "badge-pass", "OK": "badge-pass",
        "FAIL": "badge-fail", "ERROR": "badge-fail",
        "MISSING": "badge-warn",
    }.get(state, "badge-warn")
    return f"<span class='badge {cls}'>{h(state)}</span>"


def summary_card(anchor: str, title: str, state: str) -> str:
    return (
        f'<a class="summary-card" href="#{h(anchor)}">'
        f'<h3>{h(title)}</h3>{badge_html(state)}</a>'
    )


CSS = r"""
  :root {
    /* Light theme (default). Toggling data-theme="dark" on <html> flips
       these to the dark set. */
    --bg:        #ffffff;
    --fg:        #222;
    --fg-muted:  #666;
    --border:    #ccc;
    --th-bg:     #f5f5f5;
    --code-bg:   #f0f0f0;
    --card-bg:   rgba(0,0,0,0.02);
    --anchor:    #0969da;
    --banner-bg: #0d1117;
    --banner-fg: #c9d1d9;
  }
  html[data-theme="dark"] {
    --bg:        #1a1a1a;
    --fg:        #ddd;
    --fg-muted:  #999;
    --border:    #444;
    --th-bg:     #2a2a2a;
    --code-bg:   #2a2a2a;
    --card-bg:   rgba(255,255,255,0.04);
    --anchor:    #77aaff;
    --banner-bg: #0d1117;
    --banner-fg: #c9d1d9;
  }
  html, body { background: var(--bg); color: var(--fg); }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem 4rem 1.5rem;
         line-height: 1.5; scroll-behavior: smooth; }
  h1 { border-bottom: 2px solid var(--border); padding-bottom: .3em; }
  h2 { margin-top: 2.5rem; scroll-margin-top: 1rem; }
  h3.subsection { margin-top: 1.5rem; font-size: 1rem; color: var(--fg-muted); }
  a { color: var(--anchor); text-decoration: none; }
  a:hover { text-decoration: underline; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0;
          font-size: 0.9rem; }
  table.inner { margin: .5rem 0 .25rem 0; }
  th, td { border: 1px solid var(--border); padding: .4rem .6rem;
           text-align: left; vertical-align: top; }
  th { background: var(--th-bg); }
  code { background: var(--code-bg); padding: 1px 4px; border-radius: 3px;
         font-size: 0.85em; word-break: break-all; }
  pre { background: var(--code-bg); padding: 0.75rem 1rem; border-radius: 6px;
        overflow-x: auto; font-size: 0.8rem; margin: 0.5rem 0; white-space: pre-wrap; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px;
           font-size: .8rem; font-weight: 600; letter-spacing: .05em; }
  .badge-pass { background: #1b7f37; color: white; }
  .badge-fail { background: #c92a2a; color: white; }
  .badge-warn { background: #b0741a; color: white; }
  .pass { color: #1b7f37; }
  .fail { color: #c92a2a; font-weight: 500; }
  .muted { color: var(--fg-muted); font-style: italic; }
  .summary-grid { display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                  gap: 1rem; margin: 0.5rem 0 1.5rem 0; }
  .summary-card { display: block; border: 1px solid var(--border);
                  border-radius: 8px; padding: 1rem;
                  background: var(--card-bg); text-decoration: none;
                  color: var(--fg); transition: transform 0.1s, box-shadow 0.1s; }
  .summary-card:hover { transform: translateY(-2px);
                        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                        text-decoration: none; }
  .summary-card h3 { margin: 0 0 .3rem 0; font-size: 1rem; }
  .lane-label { margin: 1.5rem 0 0.25rem 0; font-size: 0.85rem;
                font-weight: 600; letter-spacing: 0.08em;
                text-transform: uppercase; color: var(--fg-muted); }
  details { margin: .5rem 0; }
  details summary { cursor: pointer; padding: .3rem 0; user-select: none;
                    color: var(--fg-muted); }
  pre.banner { background: var(--banner-bg); color: var(--banner-fg);
               padding: 1rem 1.25rem; border-radius: 6px; font-size: 0.85rem;
               line-height: 1.35; margin: 1rem 0; white-space: pre; }
  .theme-toggle { position: fixed; top: 1rem; right: 1rem; z-index: 10;
                  padding: 0.4rem 0.75rem; font-size: 0.85rem;
                  border: 1px solid var(--border); background: var(--card-bg);
                  color: var(--fg); border-radius: 6px; cursor: pointer;
                  font-family: inherit; }
  .theme-toggle:hover { background: var(--th-bg); }
"""


THEME_SCRIPT = r"""
  (function() {
    // Priority: 1) saved preference in localStorage,
    //           2) OS preference via prefers-color-scheme,
    //           3) default to light.
    var saved = null;
    try { saved = localStorage.getItem('ci-report-theme'); } catch (e) {}
    var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var initial = saved || (prefersDark ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', initial);

    function updateLabel() {
      var btn = document.getElementById('theme-toggle-btn');
      if (!btn) return;
      var cur = document.documentElement.getAttribute('data-theme');
      btn.textContent = cur === 'dark' ? 'Light mode' : 'Dark mode';
    }
    document.addEventListener('DOMContentLoaded', function() {
      updateLabel();
      var btn = document.getElementById('theme-toggle-btn');
      if (!btn) return;
      btn.addEventListener('click', function() {
        var cur = document.documentElement.getAttribute('data-theme');
        var next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        try { localStorage.setItem('ci-report-theme', next); } catch (e) {}
        updateLabel();
      });
    });
  })();
"""


def main() -> int:
    munit_data     = read_json(REPO_ROOT / "munit-scan"     / "munit-summary.json")
    mulesoft_data  = read_json(REPO_ROOT / "mulesoft-scan"  / "security-report.json")
    gitleaks_data  = read_json(REPO_ROOT / "gitleaks-scan"  / "gitleaks-report.json")
    sbom_data      = read_json(REPO_ROOT / "cyclonedx-scan" / "sbom.json")
    osv_data       = read_json(REPO_ROOT / "osv-scan"       / "osv-report.json")

    mu_state, mu_body = render_munit(munit_data)
    nm_state, nm_body = render_newman(
        REPO_ROOT / "newman-scan" / "newman.json",
        REPO_ROOT / "newman-scan" / "junit.xml",
    )
    jm_state, jm_body = render_jmeter(REPO_ROOT / "jmeter-scan" / "results.jtl")
    ms_state, ms_body = render_mulesoft(mulesoft_data)
    gl_state, gl_body = render_gitleaks(gitleaks_data)
    sb_state, sb_body = render_sbom(sbom_data)
    osv_state, osv_body = render_osv(osv_data)
    sn_state, sn_body = render_sonar()

    run_url = (os.environ.get("GITHUB_SERVER_URL", "") + "/"
               + os.environ.get("GITHUB_REPOSITORY", "") + "/actions/runs/"
               + os.environ.get("GITHUB_RUN_ID", ""))
    sha = os.environ.get("GITHUB_SHA", "")
    ref = os.environ.get("GITHUB_REF_NAME", "")

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Consolidated CI Report — {h(os.environ.get('GITHUB_REPOSITORY',''))}</title>
<style>{CSS}</style>
<script>{THEME_SCRIPT}</script>
</head>
<body>

<button class="theme-toggle" id="theme-toggle-btn" type="button" aria-label="Toggle color theme">Dark mode</button>

<h1>Consolidated CI Report</h1>

<p class="muted">
  Repository: <code>{h(os.environ.get('GITHUB_REPOSITORY',''))}</code><br>
  Ref: <code>{h(ref)}</code> · Commit: <code>{h(sha[:12])}</code><br>
  Run: <a href="{h(run_url)}">{h(run_url)}</a>
</p>

<h2 id="summary">Summary</h2>

<p class="lane-label">Functional</p>
<div class="summary-grid">
  {summary_card("section-munit",   "MUnit Tests + Coverage", mu_state)}
  {summary_card("section-newman",  "Newman Integration",     nm_state)}
  {summary_card("section-jmeter",  "JMeter Performance",     jm_state)}
</div>

<p class="lane-label">Security</p>
<div class="summary-grid">
  {summary_card("section-mulesoft", "MuleSoft Best Practices", ms_state)}
  {summary_card("section-gitleaks", "Gitleaks Secrets Scan",   gl_state)}
  {summary_card("section-sbom",     "CycloneDX SBOM",          sb_state)}
  {summary_card("section-osv",      "OSV Vulnerability Scan",  osv_state)}
  {summary_card("section-sonar",    "SonarQube Mule Scan",     sn_state)}
</div>

<h2 id="section-munit">MUnit Tests + Coverage</h2>
{mu_body}

<h2 id="section-newman">Newman Integration Tests</h2>
{nm_body}

<h2 id="section-jmeter">JMeter Performance Tests</h2>
{jm_body}

<h2 id="section-mulesoft">MuleSoft Security Best-Practices Scan</h2>
{ms_body}

<h2 id="section-gitleaks">Gitleaks Secret Scan</h2>
{gl_body}

<h2 id="section-sbom">CycloneDX SBOM</h2>
{sb_body}

<h2 id="section-osv">OSV Vulnerability Scan</h2>
{osv_body}

<h2 id="section-sonar">SonarQube Mule Scan</h2>
{sn_body}

</body>
</html>
"""
    out = REPO_ROOT / "consolidated-ci-report.html"
    out.write_text(html_doc, encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
