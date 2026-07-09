# Mule Test Automation

A demo MuleSoft application paired with a comprehensive GitHub Actions CI pipeline that runs unit tests, security scans, integration tests, performance tests, and builds a deployable JAR for the Anypoint Platform.

The application itself exposes two HTTP listeners:

- `GET /hello` — returns `{"message":"Hello World!"}`
- `GET /user-posts` — fetches `/users/1` and `/posts?userId=1` from `jsonplaceholder.typicode.com` and combines them into a single JSON payload

The point of the project is the **pipeline**, not the app. Everything below documents how the pieces fit together and how to reproduce the setup.

---

## Table of Contents

- [Requirements](#requirements)
- [Project Layout](#project-layout)
- [CI/CD Pipeline Overview](#cicd-pipeline-overview)
- [GitHub Secrets](#github-secrets)
- [Deployment](#deployment)
- [Extending the Pipeline](#extending-the-pipeline)

---

## Requirements

| Tool | Version | Purpose |
| --- | --- | --- |
| JDK | 17 (Temurin) | Required by Mule Runtime 4.9 |
| Maven | 3.9+ | Build & test |
| Mule Runtime | 4.9.11 (via mule-maven-plugin) | Application runtime |
| MUnit | 3.7.0 | Test framework |
| Python | 3.9+ | Security-scan & report scripts |
| Apache Bench (`ab`) | any | Performance tests (installed by CI) |
| An Anypoint Platform account | — | To resolve Anypoint Exchange dependencies and to deploy |
| An NVD API key | — | Only needed for offline OSV/NVD scanning (optional for CI) |

Install locally on macOS:

```bash
brew install --cask temurin@17
brew install maven python@3 apache2-utils gh
```

---

## Project Layout

```
.
├── .github/
│   ├── scripts/
│   │   ├── security-scan.py              MuleSoft best-practices static analyzer
│   │   ├── dependency-check-threshold.py Threshold enforcer (legacy, kept for reuse)
│   │   ├── integration-test.sh           JSONPlaceholder integration tests
│   │   ├── performance-test.sh           Local-mock performance tests
│   │   └── render-security-report.py     Merges 4 scan outputs into one HTML
│   ├── settings.xml                      Maven settings referencing Anypoint credentials
│   └── workflows/
│       └── ci.yml                        The pipeline
├── src/
│   ├── main/
│   │   ├── mule/test-automation.xml      Application flows
│   │   └── resources/log4j2.xml          Runtime logging config
│   └── test/
│       ├── munit/test-automation-test-suite.xml   MUnit suite
│       └── resources/log4j2-test.xml     Test-time logging config
├── mule-artifact.json                    Runtime metadata (Mule 4.9, Java 17)
├── pom.xml                               Maven build config
└── README.md
```

Files that regenerate on each build and are gitignored: `target/`, `.mule/`, IDE metadata.

---

## CI/CD Pipeline Overview

`.github/workflows/ci.yml` defines a single workflow triggered by `push` / `pull_request` to `main` and by manual dispatch. It orchestrates **nine parallel and serial jobs**:

```
security-scan ──┐
gitleaks ───────┤
sbom ───────────┼─> integration-test ─> performance-test ─┐
test ───────────┘                                          ├─> consolidated-report ─> package
dependency-check ──────────────────────────────────────────┘
```

### Jobs

| Job | Purpose | Artifact |
| --- | --- | --- |
| **`test`** | Runs MUnit + enforces coverage thresholds | `test-automation-coverage-report` (HTML) |
| **`security-scan`** | Static analysis of the Mule XML against 10 MuleSoft security best practices (SEC-001…SEC-010). 80% pass threshold. | intermediate only |
| **`gitleaks`** | Scans git history for committed secrets using the default Gitleaks ruleset | intermediate only |
| **`sbom`** | Generates a CycloneDX SBOM (XML + JSON) of all Maven dependencies | intermediate only |
| **`dependency-check`** | Runs Google OSV-Scanner against the Maven dep graph. Non-blocking — always exits clean; reports are informational. Runs in parallel with everything else. | intermediate only |
| **`integration-test`** | Live HTTP test against `jsonplaceholder.typicode.com`. Gated on `test`, `security-scan`, `gitleaks`, `sbom`. | — |
| **`performance-test`** | Local-mock load test with Apache Bench. Gated on `integration-test`. | — |
| **`security-consolidated-report`** | Merges the four scan outputs into a single self-contained HTML report; deletes intermediates. Gated on `performance-test` and `dependency-check`. | `test-automation-security-report` (HTML) |
| **`package`** | `mvn package` produces the deployable Mule JAR. Gated on `security-consolidated-report`. | `test-automation-deployable-jar` |

### Scan thresholds

- **MuleSoft best practices** (`security-scan.py`): 80% pass rate required.
- **Coverage** (`pom.xml`): 80% app / 75% resource / 70% flow.
- **Performance** (`performance-test.sh`): mean ≤ 100ms, p95 ≤ 200ms, success ≥ 99% against the local mock.
- **OSV**: reports findings but does not block the build (per project decision).

### Intermediate artifact cleanup

The four security scans each upload their raw output as `sec-intermediate-*` artifacts with `retention-days: 1` (GitHub's enforced minimum). The `security-consolidated-report` job downloads them, builds the HTML, then **immediately deletes them via the REST API** so only the consolidated report remains. Requires `actions: write` permission on the consolidator job (already declared).

---

## GitHub Secrets

Add these in **Settings → Secrets and variables → Actions** on the repository:

| Secret | Required by | Where to get it |
| --- | --- | --- |
| `ANYPOINT_CLIENT_ID` | `test`, `dependency-check`, `package` | Anypoint Platform → Access Management → Connected Apps |
| `ANYPOINT_CLIENT_SECRET` | Same | Same |
| `NVD_API_KEY` | Optional (was needed for legacy OWASP Dependency-Check, now unused with OSV) | https://nvd.nist.gov/developers/request-an-api-key |

`.github/settings.xml` references `${env.ANYPOINT_CLIENT_ID}` and `${env.ANYPOINT_CLIENT_SECRET}` — Maven picks them up from the workflow's environment block.

The workflow also uses the auto-provisioned `GITHUB_TOKEN` (no configuration required) to delete intermediate artifacts.

---

## Deployment

The pipeline produces `test-automation-1.0.0-SNAPSHOT-mule-application.jar` as an artifact on every successful run. To deploy to CloudHub 2.0:

1. Download the artifact from the run's Summary page (`test-automation-deployable-jar`).
2. Upload via Runtime Manager, or use the `deploy` goal of `mule-maven-plugin`:

   ```bash
   mvn deploy \
     -DmuleDeploy \
     -Danypoint.username=<user> \
     -Danypoint.password=<pass> \
     -Danypoint.environment=<env> \
     --settings .github/settings.xml
   ```

3. The application binds to port `8081` (see `test-automation.xml`) and exposes `GET /hello` and `GET /user-posts`.

The pipeline does **not** deploy automatically — packaging is the final step and the JAR is left as a downloadable artifact by design. Add a `deploy` job to `ci.yml` if continuous deployment is wanted.

---

## Extending the Pipeline

- **Add a new security scanner**: create a new job that emits an intermediate JSON artifact under a `sec-intermediate-*` name, then extend `render-security-report.py` with a new section.
- **Adjust coverage thresholds**: edit the `<coverage>` block in `pom.xml`.
- **Adjust security thresholds**: `MIN_PASS_PERCENT` is a module constant at the top of `security-scan.py`.
- **Adjust performance thresholds**: pass `MAX_MEAN_MS`, `MAX_P95_MS`, `MIN_SUCCESS_PCT`, `REQUESTS`, `CONCURRENCY` as env vars — the workflow already sets them on the `performance-test` step.
- **Skip the pipeline on doc-only commits**: add a `paths-ignore:` filter to the `on:` block.

---

## First-time Setup (New Fork/Clone)

```bash
# 1. Clone
git clone https://github.com/<you>/test-automation.git
cd test-automation

# 2. Add the three secrets in the GitHub UI (see above).

# 3. Verify locally (requires Anypoint creds exported as env vars if you want
#    to resolve Anypoint Exchange dependencies).
export ANYPOINT_CLIENT_ID=…
export ANYPOINT_CLIENT_SECRET=…
mvn clean test --settings .github/settings.xml --batch-mode

# 4. Push a commit — the pipeline runs automatically on push to main.
```

---

## License

Demo project — no license implied. Do not use in production without hardening: the HTTP listener is plain HTTP by design (see `SEC-001` in the security scan output).
