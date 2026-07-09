#!/usr/bin/env python3
"""
Post-process the OWASP Dependency-Check JSON report and enforce a
"clean-dependency" pass-rate threshold, mirroring the 80% pattern used
by the MuleSoft security best-practices scan.

A dependency is "clean" if it has no vulnerability at or above
MIN_CVSS. Pass rate = clean / total. Build fails when pass rate falls
below MIN_PASS_PERCENT.

Environment overrides:
  MIN_PASS_PERCENT  default 80
  MIN_CVSS          default 7.0   (HIGH+)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT = REPO_ROOT / "target" / "dependency-check-report.json"

MIN_PASS_PERCENT = float(os.environ.get("MIN_PASS_PERCENT", "80"))
MIN_CVSS = float(os.environ.get("MIN_CVSS", "7.0"))


def vuln_score(vuln: dict) -> float:
    """Best-effort CVSS score, preferring v3 then v2."""
    for key in ("cvssv3", "cvssv31", "cvssv30"):
        block = vuln.get(key) or {}
        score = block.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)
    v2 = vuln.get("cvssv2") or {}
    score = v2.get("score")
    if isinstance(score, (int, float)):
        return float(score)
    # Fall back to severity string.
    sev = (vuln.get("severity") or "").upper()
    return {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}.get(sev, 0.0)


def main() -> int:
    if not REPORT.exists():
        print(f"::error::Dependency-Check report not found at {REPORT}")
        return 1

    data = json.loads(REPORT.read_text(encoding="utf-8"))
    deps = data.get("dependencies", [])
    total = len(deps)
    if total == 0:
        print("::warning::No dependencies scanned; treating as PASS.")
        return 0

    dirty = []
    for d in deps:
        for v in d.get("vulnerabilities", []) or []:
            if vuln_score(v) >= MIN_CVSS:
                dirty.append((d.get("fileName", "<unknown>"), v.get("name", "<unknown>"), vuln_score(v)))
                break

    clean = total - len({name for name, _, _ in dirty})
    pct = (clean / total) * 100
    threshold_met = pct >= MIN_PASS_PERCENT

    print(f"Total dependencies scanned: {total}")
    print(f"Clean (no CVE >= {MIN_CVSS}):  {clean}")
    print(f"Dirty:                       {total - clean}")
    print(f"Pass rate:                   {pct:.1f}% (threshold: {MIN_PASS_PERCENT}%)")
    print(f"Status:                      {'PASSED' if threshold_met else 'FAILED'}")

    if dirty:
        print("\nDependencies with vulnerabilities at or above threshold:")
        for name, cve, score in dirty[:50]:
            print(f"  - {name}: {cve} (CVSS {score})")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## 🛡️ OWASP Dependency-Check\n\n")
            fh.write(f"**Pass rate:** {clean}/{total} = **{pct:.1f}%** ")
            fh.write(f"(threshold: {MIN_PASS_PERCENT}%, minimum CVSS: {MIN_CVSS})\n\n")
            fh.write(f"**Status:** {'PASSED ✅' if threshold_met else 'FAILED ❌'}\n\n")
            if dirty:
                fh.write("| Dependency | CVE | CVSS |\n| --- | --- | --- |\n")
                for name, cve, score in dirty[:50]:
                    fh.write(f"| `{name}` | {cve} | {score} |\n")

    return 0 if threshold_met else 1


if __name__ == "__main__":
    sys.exit(main())
