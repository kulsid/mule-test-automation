# Mule Test Automation

A demo MuleSoft application paired with a GitHub Actions CI pipeline that runs MUnit tests, five parallel security scans, integration tests via Newman, performance tests via JMeter, and builds a deployable JAR for the Anypoint Platform.


The application exposes two HTTP listeners:

- `GET /hello` — returns `{"message":"Hello World!"}`
- `GET /user-posts` — fetches `/users/1` and `/posts?userId=1` from `jsonplaceholder.typicode.com` and combines them into a single JSON payload

The point of the project is the **pipeline**, not the app.

---

## Table of Contents

- [Requirements](#requirements)
- [Project Layout](#project-layout)
- [CI/CD Pipeline Overview](#cicd-pipeline-overview)
- [GitHub Secrets](#github-secrets)
- [Repository Variables](#repository-variables)
- [Deployment](#deployment)
- [Extending the Pipeline](#extending-the-pipeline)
- [First-time Setup](#first-time-setup)
- [License](#license)

---

## Requirements

Everything except the JDK and Maven is installed automatically by the workflow — you only need the first two locally if you want to build or run tests yourself.

| Tool | Version | Purpose |
| --- | --- | --- |
| JDK | 11 (Temurin) | Required by Mule Runtime 4.4 |
| Maven | 3.8.8 (pinned) | Build & test — plugins are incompatible with 3.9+ |
| Mule Runtime | 4.4.0 (Community Edition — publicly redistributable) | Application runtime |
| MUnit | 2.3.16 | Test framework |
| Anypoint Platform account | — | To resolve Anypoint Exchange plugin/connector dependencies |

> **A note on Mule versions**: this demo uses Mule **4.4.0 (Community Edition)** because the CE runtime tarball is publicly downloadable — no Enterprise Support contract required. The application flows (`http:listener`, `http:request`, DataWeave 2.0, `set-payload`, `set-variable`, `logger`) are identical across CE and EE, so the runtime test is a faithful smoke test. If you have EE credentials for `repository.mulesoft.org/nexus-ee/`, you can bump `<app.runtime>` in `pom.xml` back to `4.9.11` and change `boot-mule.sh` to fetch the EE tarball.

---

## Project Layout

```
.
├── .github/
│   ├── jmeter/
│   │   └── mule-perf.jmx                             Performance test plan (2 thread groups, assertions)
│   ├── postman/
│   │   ├── mule-integration.postman_collection.json  Integration tests (Newman-runnable)
│   │   └── local.postman_environment.json            baseUrl = http://localhost:8081
│   ├── scripts/
│   │   ├── boot-mule.sh                              Downloads Mule CE 4.4.0, deploys the JAR, waits for :8081
│   │   ├── stop-mule.sh                              Stops the Mule instance started above
│   │   ├── security-scan.py                          MuleSoft best-practices static analyzer
│   │   └── render-security-report.py                 Merges all scan outputs into one HTML
│   ├── settings.xml                                  Maven settings referencing Anypoint credentials
│   └── workflows/
│       └── ci.yml                                    The pipeline
├── src/
│   ├── main/
│   │   ├── mule/test-automation.xml                  Application flows
│   │   └── resources/log4j2.xml                      Runtime logging config
│   └── test/
│       ├── munit/test-automation-test-suite.xml      MUnit suite
│       └── resources/log4j2-test.xml                 Test-time logging config
├── .gitleaks.toml                                    Allowlist for known-safe secret patterns
├── mule-artifact.json                                Runtime metadata (Mule 4.4, Java 11)
├── pom.xml                                           Maven build config
├── LICENSE                                           Apache 2.0
└── README.md
```

Files that regenerate on each build and are gitignored: `target/`, `.mule/`, `mule/`, `.mule-dist/`, IDE metadata, `security-report.*`.

---

## CI/CD Pipeline Overview

`.github/workflows/ci.yml` defines a single workflow triggered by `push` / `pull_request` to `main` and by manual dispatch. It orchestrates **10 jobs** across two independent lanes that meet only at the final convergence node.

```
Functional lane
───────────────
   test  ─────▶  package  ─────▶  runtime-test  ─────┐
     │                                 │             │
     │                                 │             │
Security lane                          │             │
─────────────                          │             ├───▶  consolidated-report  ─────▶  build-successful
   security-scan     ┐                 │             │              (if: always())
   gitleaks          │                 │             │
   sbom              ├─────────────────┴─────────────┤
   dependency-check  │                               │
   sonar-scan        ┘                               │
```

Behavior:

- **Two lanes run in parallel.** The functional lane (`test → package → runtime-test`) and the five security scans start simultaneously.
- **`consolidated-report`** waits for **every** upstream job — MUnit (`test`), Newman + JMeter (`runtime-test`), and all five security scans. It has `if: always()`, so a failed scan renders as `MISSING` in the HTML instead of blocking the report.
- **`sonar-scan`** reads Mule XML flows and DataWeave directly from `src/main` / `src/test`. It does not need the packaged JAR — there's no bytecode analysis for a Mule app — so it doesn't wait on the functional lane.
- **`build-successful`** requires *every* upstream job to succeed. If any of the 9 jobs fails or is skipped, this job is skipped and the workflow is marked failed.
- **Artifacts are always uploaded.** Every `upload-artifact` step has `if: always()`, so a red run still leaves every report downloadable from the run summary page.

### Jobs

| Job | Purpose | Downloadable artifact(s) |
| --- | --- | --- |
| **`test`** | Runs MUnit + enforces coverage thresholds. Root of the functional lane. | `detailed-munit-report` (HTML) |
| **`package`** | `mvn package` produces the deployable Mule JAR. Gated on `test`. | `deployable-jar` |
| **`runtime-test`** | Boots Mule CE 4.4.0 Standalone on `:8081`, runs the Postman collection with **Newman** (integration), then the JMeter plan (performance) against the live listener. Gated on `package`. | `detailed-integration-report` (Newman HTML), `detailed-performance-report` (JMeter dashboard) |
| **`security-scan`** | Static analysis of the Mule XML against 10 MuleSoft security best practices (SEC-001…SEC-010). 80% pass threshold. | (feeds consolidated report only) |
| **`gitleaks`** | Scans git history for committed secrets. Uses `.gitleaks.toml` at repo root to allowlist known-safe template patterns (Anypoint auth format, ephemeral SonarQube admin rotation). | (feeds consolidated report only) |
| **`sbom`** | Generates a CycloneDX SBOM (XML + JSON) of all Maven dependencies. | (feeds consolidated report only) |
| **`dependency-check`** | Runs Google OSV-Scanner against the Maven dep graph. Non-blocking — always exits clean; reports are informational. | (feeds consolidated report only) |
| **`sonar-scan`** | Boots an ephemeral **SonarQube 9.9 Community** container with the `mule-sonarqube-plugin` (from `mulesoft-catalyst/mule-sonarqube-plugin`) baked in. Runs `sonar-scanner` against `src/main` and `src/test`, waits for background analysis, dumps the SonarQube API to JSON, and exports the native HTML via `sonar-report`. | `detailed-sonar-report` (SonarQube's native HTML) |
| **`security-consolidated-report`** | Merges every job's compact intermediate — MUnit summary, Newman JSON, JMeter JTL, plus the five security scan outputs — into a single self-contained HTML report with a light/dark theme toggle and clickable summary cards that scroll to each section. Gated on all 7 upstream jobs with `if: always()`. Fails if any upstream job did not succeed (so the workflow status accurately reflects the underlying jobs). | `consolidated-report` (HTML) |
| **`build-successful`** | Convergence node — purely for graph aesthetics. Runs only when both `runtime-test` and `security-consolidated-report` succeed. Produces no artifacts. | — |

### Thresholds

Which signals are gating and which are informational. The tunable numeric values live in [Repository Variables](#repository-variables) below.

| Signal | Default | Blocking? |
| --- | ---: | --- |
| MUnit coverage (application / resource / flow) | 80% / 75% / 70% | Yes |
| MuleSoft best-practices pass rate | 80% | Yes |
| JMeter latency (`/hello` sample) | ≤ 500ms | Yes |
| JMeter latency (`/user-posts` sample) | ≤ 2000ms (looser — fans out to JSONPlaceholder) | Yes |
| JMeter failed samples | 0 | Yes |
| Gitleaks secrets | any real finding | Yes |
| OSV vulnerabilities | any finding | No — informational |
| SonarQube quality gate | any threshold | No — Community Edition constraint |

### Artifact model

Two classes of artifacts survive the run:

1. **`consolidated-report`** — the single self-contained HTML rollup produced by `security-consolidated-report`. Includes light/dark theme toggle, per-section deep-dive tables (test-by-test, per-request, per-endpoint), the Gitleaks ASCII banner, and clickable summary cards that scroll to each section.
2. **`detailed-*` reports** — each tool's own native, interactive report, preserved separately for drill-down:
   - `detailed-munit-report` — MUnit's line-by-line coverage HTML
   - `detailed-integration-report` — Newman's htmlextra HTML
   - `detailed-performance-report` — JMeter's HTML dashboard folder
   - `detailed-sonar-report` — SonarQube's `sonar-report` HTML export

Additionally, `deployable-jar` is uploaded from the `package` job as the actual build output.

Every producing job also emits a compact `sec-intermediate-*` intermediate (with `retention-days: 1` — GitHub's enforced minimum): `munit`, `newman`, `jmeter`, `mulesoft`, `gitleaks`, `cyclonedx`, `osv`, `sonar`. These are the *inputs* to the consolidator; they are **deleted via the REST API** at the end of `security-consolidated-report` so only the polished artifacts remain visible. Requires `actions: write` permission on the consolidator job (already declared).

---

## GitHub Secrets

Add these in **Settings → Secrets and variables → Actions → Secrets tab**:

| Secret | Required by | Where to get it |
| --- | --- | --- |
| `ANYPOINT_CLIENT_ID` | `test`, `package`, `dependency-check` | Anypoint Platform → Access Management → Connected Apps |
| `ANYPOINT_CLIENT_SECRET` | Same | Same |

> `runtime-test` deliberately does **not** consume the Anypoint credentials — it fetches the publicly hosted Mule CE 4.4.0 tarball, keeping the runtime smoke test unauth'd and reproducible for anyone forking the repo.

`.github/settings.xml` references the Anypoint credentials via Maven's `${env.VAR}` interpolation — Maven picks them up from the workflow's environment block. The workflow also uses the auto-provisioned `GITHUB_TOKEN` (no configuration required) to delete intermediate artifacts.

---

## Repository Variables

Set these in **Settings → Secrets and variables → Actions → Variables tab**. All are **optional** — the workflow falls back to the defaults shown below if a variable is unset, so a fresh fork works out of the box.

| Variable | Default | Consumed by |
| --- | ---: | --- |
| `MUNIT_COVERAGE_APP` | `80` | `test` job — MUnit application coverage % |
| `MUNIT_COVERAGE_RESOURCE` | `75` | `test` job — MUnit resource coverage % |
| `MUNIT_COVERAGE_FLOW` | `70` | `test` job — MUnit flow coverage % |
| `MULESOFT_SECURITY_MIN_PASS_PERCENT` | `80` | `security-scan` job — % of SEC-001..SEC-010 that must pass |
| `JMETER_USERS` | `10` | `runtime-test` job — concurrent users per JMeter thread group |
| `JMETER_LOOPS` | `10` | `runtime-test` job — request loops per user |
| `JMETER_RAMPUP_S` | `1` | `runtime-test` job — thread ramp-up window in seconds |
| `JMETER_MAX_SAMPLE_MS` | `500` | `runtime-test` job — per-sample timeout for `/hello` |
| `JMETER_MAX_SAMPLE_MS_DOWNSTREAM` | `2000` | `runtime-test` job — per-sample timeout for `/user-posts` (looser, fans out to JSONPlaceholder) |
| `JMETER_MAX_FAILURES` | `0` | `runtime-test` job — allowed failing samples before the step fails |

Editing any of these in the UI takes effect on the next workflow run — no code change or PR required.

---

## Deployment

The pipeline produces `test-automation-1.0.0-SNAPSHOT-mule-application.jar` as an artifact on every successful run. To deploy to CloudHub 2.0:

1. Download the artifact from the run's Summary page (`deployable-jar`).
2. Upload via Runtime Manager, or use the `deploy` goal of `mule-maven-plugin`:

   ```bash
   mvn deploy \
     -DmuleDeploy \
     -Danypoint.username=<user> \
     -Danypoint.password=<pass> \
     -Danypoint.environment=<env> \
     --settings .github/settings.xml
   ```

3. The application binds to port `8081` and exposes `GET /hello` and `GET /user-posts`.

The pipeline does **not** deploy automatically — the JAR is left as a downloadable artifact by design. Add a `deploy` job to `ci.yml` if continuous deployment is wanted.

---

## Extending the Pipeline

- **Add a new security scanner**: create a new job that emits an intermediate JSON artifact under a `sec-intermediate-*` name, then extend `render-security-report.py` with a new section.
- **Adjust any numeric threshold**: change the corresponding [Repository Variable](#repository-variables) in the GitHub UI — no code change needed. Applies to all coverage, security-scan, and JMeter thresholds.
- **Add a new integration assertion**: open `.github/postman/mule-integration.postman_collection.json` in Postman, add a request or `pm.test`, and commit. Newman picks up the change automatically.
- **Skip the pipeline on doc-only commits**: add a `paths-ignore:` filter to the `on:` block of `ci.yml`.

---

## First-time Setup

```bash
# 1. Clone
git clone https://github.com/<you>/mule-test-automation.git
cd mule-test-automation

# 2. Add the two Anypoint secrets in the GitHub UI (see GitHub Secrets above).

# 3. Push a commit — the pipeline runs automatically on push to main.
git commit --allow-empty -m "trigger initial CI run"
git push
```

---

## License

Licensed under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE) for the full text.
