#!/usr/bin/env python3
"""
Static security scan for the Mule application, aligned with MuleSoft's
recommended security best practices.

Scans src/main/mule/**/*.xml, src/main/resources/**, pom.xml, and workflow
YAML. Each check reports PASS or FAIL. The build fails if fewer than
MIN_PASS_PERCENT of the checks pass.

Outputs:
  - security-report.json (machine-readable — read by render-security-report.py)
  - stdout: the same content in Markdown for humans watching the CI log

Reference: https://docs.mulesoft.com/general/security-best-practices
"""
from __future__ import annotations

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Threshold sourced from the MULESOFT_SECURITY_MIN_PASS_PERCENT GitHub
# Actions repository variable, injected via the workflow's env: block.
# Falls back to 80 for local runs (`python3 security-scan.py`).
try:
    MIN_PASS_PERCENT = int(os.environ.get("MULESOFT_SECURITY_MIN_PASS_PERCENT", "80"))
except ValueError:
    MIN_PASS_PERCENT = 80
REPO_ROOT = Path(__file__).resolve().parents[2]
MULE_DIR = REPO_ROOT / "src" / "main" / "mule"
RESOURCES_DIR = REPO_ROOT / "src" / "main" / "resources"
POM = REPO_ROOT / "pom.xml"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

NS = {
    "mule": "http://www.mulesoft.org/schema/mule/core",
    "http": "http://www.mulesoft.org/schema/mule/http",
    "secure-properties": "http://www.mulesoft.org/schema/mule/secure-properties",
    "tls": "http://www.mulesoft.org/schema/mule/tls",
}


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return ""


def mule_xml_files() -> list[Path]:
    return sorted(MULE_DIR.rglob("*.xml")) if MULE_DIR.exists() else []


def all_property_files() -> list[Path]:
    if not RESOURCES_DIR.exists():
        return []
    return sorted(
        list(RESOURCES_DIR.rglob("*.properties")) + list(RESOURCES_DIR.rglob("*.yaml"))
    )


# --- Individual checks ---------------------------------------------------- #

def check_https_listeners() -> tuple[bool, str]:
    """SEC-001: HTTPS listener connections. Every http:listener-connection
    should use protocol=HTTPS (or be explicitly allow-listed as an internal
    demo endpoint)."""
    findings = []
    for f in mule_xml_files():
        content = read(f)
        for match in re.finditer(
            r"<http:listener-connection\b([^>]*)/?>", content, re.DOTALL
        ):
            attrs = match.group(1)
            proto = re.search(r'protocol\s*=\s*"([^"]+)"', attrs)
            if not proto or proto.group(1).upper() != "HTTPS":
                findings.append(f"{f.relative_to(REPO_ROOT)}: listener not HTTPS")
    if findings:
        return False, "; ".join(findings[:3])
    return True, "All http:listener-connection elements use HTTPS"


def check_https_requests() -> tuple[bool, str]:
    """SEC-002: outbound HTTP requests use HTTPS."""
    findings = []
    for f in mule_xml_files():
        content = read(f)
        for match in re.finditer(
            r"<http:request-connection\b([^>]*)/?>", content, re.DOTALL
        ):
            attrs = match.group(1)
            proto = re.search(r'protocol\s*=\s*"([^"]+)"', attrs)
            if not proto or proto.group(1).upper() != "HTTPS":
                findings.append(f"{f.relative_to(REPO_ROOT)}: request not HTTPS")
    if findings:
        return False, "; ".join(findings[:3])
    return True, "All http:request-connection elements use HTTPS"


def check_no_hardcoded_secrets() -> tuple[bool, str]:
    """SEC-003: no hardcoded credentials in Mule XML."""
    patterns = [
        (r'password\s*=\s*"(?!\s*\$\{)([^"]+)"', "password"),
        (r'clientSecret\s*=\s*"(?!\s*\$\{)([^"]+)"', "clientSecret"),
        (r'accessKey\s*=\s*"(?!\s*\$\{)([^"]+)"', "accessKey"),
        (r'secretKey\s*=\s*"(?!\s*\$\{)([^"]+)"', "secretKey"),
        (r'apiKey\s*=\s*"(?!\s*\$\{)([^"]+)"', "apiKey"),
    ]
    findings = []
    for f in mule_xml_files():
        content = read(f)
        for pat, label in patterns:
            for m in re.finditer(pat, content, re.IGNORECASE):
                val = m.group(1).strip()
                if val and not val.startswith("${"):
                    findings.append(
                        f"{f.relative_to(REPO_ROOT)}: {label} literal"
                    )
    if findings:
        return False, "; ".join(findings[:3])
    return True, "No hardcoded credentials found in Mule XML"


def check_secure_properties_usage() -> tuple[bool, str]:
    """SEC-004: if property files exist, secure-properties or an equivalent
    encrypted-property mechanism should be configured. Otherwise pass by
    default (no properties to protect)."""
    if not all_property_files():
        return True, "No property files present (nothing to secure)"
    for f in mule_xml_files():
        content = read(f)
        if "secure-properties:config" in content or "secure::" in content:
            return True, "secure-properties config detected"
    return False, "Property files exist but no secure-properties config found"


def check_tls_context_when_https() -> tuple[bool, str]:
    """SEC-005: any HTTPS listener should reference a tls:context (server-
    side TLS). Client-side HTTPS with default JVM trust is acceptable."""
    findings = []
    for f in mule_xml_files():
        content = read(f)
        # Only enforce for listener-connections
        for m in re.finditer(
            r"<http:listener-connection\b[^>]*protocol\s*=\s*\"HTTPS\"[^>]*>(.*?)</http:listener-connection>|<http:listener-connection\b[^>]*protocol\s*=\s*\"HTTPS\"[^>]*/>",
            content,
            re.DOTALL,
        ):
            block = m.group(0)
            if "tls:context" not in block:
                findings.append(
                    f"{f.relative_to(REPO_ROOT)}: HTTPS listener missing tls:context"
                )
    if findings:
        return False, "; ".join(findings[:3])
    return True, "All HTTPS listeners include a tls:context (or none configured)"


def check_no_wildcard_bind() -> tuple[bool, str]:
    """SEC-006: avoid binding listeners to 0.0.0.0. CloudHub-hosted apps
    should bind to 0.0.0.0 by policy — flag but do not fail if only demo
    ports are used. Treated as informational: passes if there is at most
    one such binding (demo tolerance)."""
    count = 0
    for f in mule_xml_files():
        content = read(f)
        count += len(
            re.findall(r'<http:listener-connection\b[^>]*host\s*=\s*"0\.0\.0\.0"', content)
        )
    if count > 1:
        return False, f"{count} listeners bound to 0.0.0.0 (limit for demo: 1)"
    return True, f"{count} listener(s) bound to 0.0.0.0 within demo tolerance"


def check_logger_no_sensitive_payload() -> tuple[bool, str]:
    """SEC-007: loggers should not dump payload/attributes wholesale, which
    can leak PII or credentials."""
    findings = []
    risky = re.compile(
        r"<logger\b[^>]*message\s*=\s*\"[^\"]*#\[\s*(payload|attributes)\s*\]\"",
        re.IGNORECASE,
    )
    for f in mule_xml_files():
        content = read(f)
        for m in risky.finditer(content):
            findings.append(
                f"{f.relative_to(REPO_ROOT)}: logger dumps full {m.group(1)}"
            )
    if findings:
        return False, "; ".join(findings[:3])
    return True, "No loggers dump full payload/attributes"


def check_error_handling_configured() -> tuple[bool, str]:
    """SEC-008: every flow with an inbound listener should have an error
    handler configured (either inline or a global one). Missing error
    handlers can leak stack traces."""
    problems = []
    for f in mule_xml_files():
        content = read(f)
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            continue
        for flow in root.findall(".//{http://www.mulesoft.org/schema/mule/core}flow"):
            has_listener = any(
                child.tag.endswith("}listener") for child in flow.iter()
            )
            if not has_listener:
                continue
            has_error_handler = any(
                child.tag.endswith("}error-handler") for child in flow.iter()
            )
            has_global_handler = any(
                el.tag.endswith("}error-handler") for el in root
            )
            if not (has_error_handler or has_global_handler):
                problems.append(
                    f"{f.relative_to(REPO_ROOT)}: flow "
                    f"{flow.get('name', '<unnamed>')} has no error-handler"
                )
    if problems:
        return False, "; ".join(problems[:3])
    return True, "All listener-fronted flows have error handling"


def check_pom_dependency_versions_pinned() -> tuple[bool, str]:
    """SEC-009: dependency versions must be pinned (no SNAPSHOT/RELEASE/
    LATEST) so builds are reproducible and auditable."""
    content = read(POM)
    if not content:
        return True, "No pom.xml (skipped)"
    bad = re.findall(
        r"<version>\s*(LATEST|RELEASE|[\w\.\-]*-SNAPSHOT)\s*</version>",
        content,
        re.IGNORECASE,
    )
    # ignore the project's own -SNAPSHOT version
    own_snapshot = re.search(r"<version>\s*[\w\.\-]*-SNAPSHOT\s*</version>", content)
    if own_snapshot:
        bad = [b for b in bad if b.lower() != own_snapshot.group(0).lower().replace("<version>", "").replace("</version>", "").strip()]
        # keep it simple: subtract one occurrence of the project's own snapshot
        if own_snapshot.group(0):
            bad = bad[:-1] if bad else bad
    if bad:
        return False, f"Unpinned dependency versions: {bad}"
    return True, "All dependencies have pinned versions"


def check_ci_uses_secrets_not_literals() -> tuple[bool, str]:
    """SEC-010: CI workflow must pass Anypoint credentials via `secrets`,
    never as literals."""
    if not WORKFLOWS_DIR.exists():
        return True, "No workflows dir (skipped)"
    findings = []
    for f in WORKFLOWS_DIR.rglob("*.yml"):
        content = read(f)
        # any occurrence of ANYPOINT_CLIENT_ID / _SECRET must reference secrets.
        for var in ("ANYPOINT_CLIENT_ID", "ANYPOINT_CLIENT_SECRET"):
            for m in re.finditer(rf"{var}\s*:\s*(.+)", content):
                val = m.group(1).strip()
                if val and "secrets." not in val:
                    findings.append(
                        f"{f.relative_to(REPO_ROOT)}: {var} not sourced from secrets"
                    )
    if findings:
        return False, "; ".join(findings[:3])
    return True, "CI credentials sourced from secrets"


CHECKS: list[tuple[str, str, callable]] = [
    ("SEC-001", "HTTPS on all listeners", check_https_listeners),
    ("SEC-002", "HTTPS on all outbound requests", check_https_requests),
    ("SEC-003", "No hardcoded credentials in Mule XML", check_no_hardcoded_secrets),
    ("SEC-004", "Secure properties configured for property files", check_secure_properties_usage),
    ("SEC-005", "TLS context on HTTPS listeners", check_tls_context_when_https),
    ("SEC-006", "Wildcard bind (0.0.0.0) limited", check_no_wildcard_bind),
    ("SEC-007", "Loggers do not dump full payload/attributes", check_logger_no_sensitive_payload),
    ("SEC-008", "Error handlers on listener-fronted flows", check_error_handling_configured),
    ("SEC-009", "Dependency versions pinned in pom.xml", check_pom_dependency_versions_pinned),
    ("SEC-010", "CI credentials sourced from GitHub secrets", check_ci_uses_secrets_not_literals),
]


def main() -> int:
    results = []
    for cid, title, fn in CHECKS:
        try:
            passed, detail = fn()
        except Exception as e:  # noqa: BLE001
            passed, detail = False, f"check errored: {e!r}"
        results.append(
            {"id": cid, "title": title, "passed": passed, "detail": detail}
        )

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    pct = (passed / total) * 100 if total else 0.0
    threshold_met = pct >= MIN_PASS_PERCENT

    # JSON report
    (REPO_ROOT / "security-report.json").write_text(
        json.dumps(
            {
                "threshold_percent": MIN_PASS_PERCENT,
                "pass_percent": round(pct, 2),
                "passed": passed,
                "total": total,
                "threshold_met": threshold_met,
                "checks": results,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Console echo — assemble a markdown table so anyone tailing the CI
    # log gets a readable summary. Not written to disk; the JSON above
    # is the durable output that render-security-report.py consumes.
    md_lines = [
        "# MuleSoft Security Best-Practices Scan",
        "",
        f"**Pass rate:** {passed}/{total} = **{pct:.1f}%** (threshold: {MIN_PASS_PERCENT}%)",
        f"**Status:** {'PASSED ✅' if threshold_met else 'FAILED ❌'}",
        "",
        "| ID | Check | Result | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for r in results:
        mark = "PASS" if r["passed"] else "FAIL"
        md_lines.append(f"| {r['id']} | {r['title']} | **{mark}** | {r['detail']} |")
    md_lines.append("")
    md_lines.append(
        "Reference: https://docs.mulesoft.com/general/security-best-practices"
    )
    print("\n".join(md_lines))

    # Step summary — compact form. GitHub renders $GITHUB_STEP_SUMMARY at a
    # fixed large font, so a 10-row wide table hogs the run page. Emit only
    # the headline + any failing checks; the full table lives in the
    # consolidated HTML report artifact.
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        failing = [r for r in results if not r["passed"]]
        summary_lines = [
            "### MuleSoft Security Best-Practices Scan",
            "",
            f"**Pass rate:** {passed}/{total} ({pct:.0f}%) — "
            f"{'**PASSED** ✅' if threshold_met else '**FAILED** ❌'}",
            "",
        ]
        if failing:
            summary_lines.append(f"**Failing checks ({len(failing)}):**")
            for r in failing:
                summary_lines.append(f"- ❌ **{r['id']}** {r['title']}")
                summary_lines.append(f"  <sub>{r['detail']}</sub>")
        else:
            summary_lines.append("_All checks passing._")
        summary_lines += [
            "",
            "<sub>Full report: download the `consolidated-report` artifact.</sub>",
            "",
        ]
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(summary_lines))

    return 0 if threshold_met else 1


if __name__ == "__main__":
    sys.exit(main())
