# OWASP API Security Testing Framework

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/www-project-api-security-testing-framework/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![CI](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-229%20passing-brightgreen.svg)](#)
[![Release](https://img.shields.io/github/v/release/OWASP/www-project-api-security-testing-framework?include_prereleases&label=latest)](https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest)

A comprehensive automated testing framework for detecting API security vulnerabilities based on the **OWASP API Security Top 10 2023**.

---

## Quick Start

### 1. Prerequisites

| Requirement | Version | Why |
|---|---|---|
| **Java** | 21+ | The Scanner core uses Java 21 **virtual threads** for high-concurrency scanning |
| **Maven** | 3.6+ | Required only if building from source |

### 2. Download (recommended)

Download the latest pre-built JAR directly from the [GitHub Releases page](https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest) — no build step needed:

```bash
# Download the latest beta release
curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v1.1.0-beta.jar
```

Or build from source:

```bash
git clone https://github.com/OWASP/www-project-api-security-testing-framework.git
cd www-project-api-security-testing-framework
mvn clean package -DskipTests
# JAR is at: target/api-security-testing-framework-1.0-SNAPSHOT.jar
```

### 3. Run your first scan (copy-paste ready)

**Option A — Inline flags** (quickest):
```bash
java -jar astf-v1.1.0-beta.jar \
  -u https://api.example.com \
  --token "YOUR_BEARER_TOKEN" \
  -f HTML -o results.html -v
```

**Option B — Config file** (recommended for repeatable scans):
```bash
java -jar astf-v1.1.0-beta.jar -c docs/examples/scan-config.yaml
```

**Option C — Against OWASP crAPI** (zero-config proof of concept):
```bash
java -jar astf-v1.1.0-beta.jar \
  -u http://crapi.apisec.ai \
  -f HTML -o crapi-report.html --timeout 3
# Auto-discovers 832 endpoints, detects 11 vulnerability types
```

Open the HTML report:
```bash
# macOS/Linux
open crapi-report.html

# Windows
start crapi-report.html
```

---

## Releases

Releases are published automatically when a version tag is pushed. The workflow runs all 229 tests, builds the fat JAR, and attaches it to the GitHub Release.

| Tag format | Release type | Example |
|---|---|---|
| `v*-beta` | Pre-release | `v1.1.0-beta` ← current |
| `v*-rc*` | Release candidate | `v1.0.0-rc1` |
| `v*` (no suffix) | Stable release | `v1.0.0` |

**[→ View all releases](https://github.com/OWASP/www-project-api-security-testing-framework/releases)**

The JAR asset on each release is named `astf-<tag>.jar`, e.g. `astf-v1.1.0-beta.jar`. Use this name in your CI pipelines to pin a specific version.

---

## Configuration Basics

The simplest config file — target URL plus a Bearer token:

```yaml
# docs/examples/quickstart.yaml
target:
  url: "https://api.example.com"

auth:
  bearerToken: "eyJhbGciOiJIUzI1NiJ9..."

output:
  format: "HTML"
  file: "results.html"
  verbose: true
```

For API key authentication:

```yaml
target:
  url: "https://api.example.com"

auth:
  apiKey: "sk-abc123"
  apiKeyHeader: "X-API-Key"   # defaults to X-API-Key if omitted
```

See [`docs/examples/scan-config.yaml`](docs/examples/scan-config.yaml) for the full reference covering proxy, custom headers, thread count, rate limiting, test selection, and output options.

---

## CLI Reference

```
Usage: astf [-hvV] [--no-discovery] [--api-key=<apiKey>]
            [--api-key-header=<apiKeyHeader>] [-c=<configFile>]
            [--endpoints-file=<file>] [--exclude-tests=<ids>] [-f=<format>]
            [-o=<outputFile>] [--password=<password>] [--proxy=<proxyUrl>]
            [-t=<threads>] [--test-cases=<ids>] [--timeout=<minutes>]
            [--token=<bearerToken>] [-u=<targetUrl>] [--username=<username>]
            [--header=<Key:Value>]...
```

| Flag | Short | Description | Default |
|---|---|---|---|
| `--url` | `-u` | Target API base URL | — |
| `--config` | `-c` | Path to YAML/JSON config file | — |
| `--format` | `-f` | Output: `JSON`, `HTML`, `SARIF`, `XML` | `JSON` |
| `--output` | `-o` | Output file path | stdout |
| `--token` | | Bearer token (`Authorization: Bearer …`) | — |
| `--api-key` | | API key value | — |
| `--api-key-header` | | Header name for API key | `X-API-Key` |
| `--username` | | Basic auth username | — |
| `--password` | | Basic auth password | — |
| `--header` | | Extra header `Key:Value` (repeatable) | — |
| `--proxy` | | Proxy URL e.g. `http://proxy:8080` | — |
| `--endpoints-file` | | File of endpoints to test (`METHOD /path` per line). Skips discovery. | — |
| `--threads` | `-t` | Concurrent threads | `10` |
| `--timeout` | | Scan timeout in minutes | `30` |
| `--test-cases` | | Comma-separated test case IDs to run | all |
| `--exclude-tests` | | Comma-separated test case IDs to skip | none |
| `--no-discovery` | | Disable auto endpoint discovery | false |
| `--verbose` | `-v` | Verbose output | false |
| `--version` | `-V` | Print version | — |
| `--help` | `-h` | Show help | — |

### Endpoint Input Precedence

When multiple endpoint sources are configured, ASTF uses this order (highest wins):

| Priority | Source | How |
|---|---|---|
| 1 | `--endpoints-file` CLI flag | Overrides everything |
| 2 | `endpoints:` inline YAML block | In config file |
| 3 | `endpointsFile:` YAML key | In config file |
| 4 | Automatic discovery | OpenAPI probing + common paths |
| 5 | Fallback hardcoded paths | When discovery finds nothing |

```bash
# Scan only specific endpoints from a file
java -jar astf-v1.1.0-beta.jar -u https://api.example.com \
  --endpoints-file my-endpoints.txt --token "TOKEN"

# my-endpoints.txt format:
# GET  /api/v1/users
# GET  /api/v1/users/{id}
# POST /api/v1/users
# DELETE /api/v1/users/{id}
```

### Exit Codes

| Code | Meaning | CI usage |
|---|---|---|
| `0` | Scan completed — no findings | Pipeline passes |
| `1` | Scan completed — findings detected | Gate on HIGH/CRITICAL (see CI/CD section) |
| `2` | Scan error (bad config, network failure) | Always fail pipeline |

---

## Test Case Catalog

100% coverage of the **OWASP API Security Top 10 2023**, plus GraphQL and gRPC:

| ID | Name | Implementation Class | What It Detects |
|---|---|---|---|
| `ASTF-API1-2023` | Broken Object Level Authorization | `BrokenObjectLevelAuthorizationTestCase` | BOLA/IDOR — manipulates numeric and UUID IDs in URL paths to access other users' resources |
| `ASTF-API2-2023` | Broken Authentication | `BrokenAuthenticationTestCase` | Missing auth, JWT `none` algorithm, expired tokens, tokens in URL, 2FA bypass with guessable OTPs, insecure session cookies |
| `ASTF-API3-2023` | Broken Object Property Level Authorization | `BrokenObjectPropertyLevelAuthorizationTestCase` | Password/secret fields in responses (excessive data exposure), mass assignment via POST |
| `ASTF-API4-2023` | Unrestricted Resource Consumption | `UnrestrictedResourceConsumptionTestCase` | Missing `X-RateLimit-*` / `Retry-After` headers on resource-heavy endpoints |
| `ASTF-API5-2023` | Broken Function Level Authorization | `BrokenFunctionLevelAuthorizationTestCase` | Admin endpoints (`/admin`, `/internal`, `/manage`) reachable without elevated privileges |
| `ASTF-API6-2023` | Unrestricted Access to Sensitive Flows | `UnrestrictedAccessToSensitiveFlowsTestCase` | Rate limiting and bot protection absent on login, OTP, payment, and password-reset flows |
| `ASTF-API7-2023` | Server-Side Request Forgery | `ServerSideRequestForgeryTestCase` | SSRF via `url`, `webhook`, `redirect`, `callback` parameters — injects AWS metadata URL |
| `ASTF-API8-2023` | Security Misconfiguration | `SecurityMisconfigurationTestCase` | Missing security headers, verbose error messages, stack traces in responses |
| `ASTF-API9-2023` | Improper Inventory Management | `ImproperInventoryManagementTestCase` | Deprecated API versions (`/v1`, `/v2`), shadow endpoints, exposed API docs |
| `ASTF-API10-2023` | Unsafe Consumption of APIs | `UnsafeConsumptionOfApisTestCase` | Injection via webhook/integration endpoints, open redirect in callback URLs |
| `ASTF-GRAPHQL-2023` | GraphQL Security | `GraphQLSecurityTestCase` | Introspection enabled, field suggestion leakage, query depth attacks, batch query abuse |
| `ASTF-GRPC-2023` | gRPC Endpoint Detection | `GrpcEndpointDetectionTestCase` | gRPC service detection, server reflection enabled (schema enumeration risk) |

Run only specific test cases:
```bash
java -jar astf-v1.1.0-beta.jar -u https://api.example.com \
  --test-cases ASTF-API1-2023,ASTF-API2-2023

java -jar astf-v1.1.0-beta.jar -u https://api.example.com \
  --exclude-tests ASTF-GRAPHQL-2023,ASTF-GRPC-2023
```

---

## Reporting & Interpreting Results

### Output Formats

| Format | Flag | Best for |
|---|---|---|
| **HTML** | `-f HTML` | Human review — severity-coloured findings with evidence and remediation |
| **JSON** | `-f JSON` | Programmatic processing — full `Finding` object with all fields |
| **SARIF** | `-f SARIF` | GitHub Code Scanning dashboards and security tooling |
| **XML** | `-f XML` | Legacy CI systems and enterprise reporting tools |

### Understanding a Finding

Every finding contains these key fields (shown using a real crAPI result):

```json
{
  "id": "a3f2c1d0-...",
  "title": "JWT 'none' Algorithm Accepted",
  "severity": "CRITICAL",
  "testCaseId": "ASTF-API2-2023",
  "endpoint": "GET /api/search",
  "description": "The server accepted a JWT token signed with the 'none' algorithm,
                  meaning no signature validation is performed.",
  "evidence": "Server returned HTTP 200 when presented with a JWT using 'none' algorithm",
  "recommendation": "Reject tokens with 'alg: none'. In Spring Security, configure
                     NimbusJwtDecoder with an explicit algorithm allowlist."
}
```

| Field | What it tells you |
|---|---|
| `severity` | CRITICAL / HIGH / MEDIUM / LOW — prioritise fixes by this |
| `evidence` | The exact HTTP signal that confirmed the vulnerability |
| `recommendation` | Framework-specific fix instructions for the developer |
| `testCaseId` | Which ASTF check triggered — maps to an OWASP category |
| `endpoint` | The exact method + path to patch |

---

## CI/CD Integration

### GitHub Actions — Scan on Every Pull Request

```yaml
name: API Security Scan
on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'

      - name: Download ASTF
        run: |
          curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v1.1.0-beta.jar

      - name: Run ASTF scan
        run: |
          java -jar astf-v1.1.0-beta.jar \
            -u ${{ secrets.API_URL }} \
            --token ${{ secrets.API_TOKEN }} \
            -f SARIF -o results.sarif \
            --timeout 10 || echo "ASTF_EXIT=$?" >> $GITHUB_ENV

      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        continue-on-error: true

      - name: Fail build on HIGH or CRITICAL findings
        run: |
          if [ "${ASTF_EXIT}" = "1" ]; then
            echo "ASTF detected security findings — review SARIF report"
            exit 1
          fi
```

### Gate on HIGH/CRITICAL only (not every finding)

```bash
java -jar astf-v1.1.0-beta.jar \
  -u $API_URL --token $TOKEN -f JSON -o results.json

HIGH_CRIT=$(jq '[.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' results.json)
if [ "$HIGH_CRIT" -gt "0" ]; then
  echo "Build failed: $HIGH_CRIT HIGH/CRITICAL findings detected"
  exit 1
fi
```

---

## Project Structure

```
www-project-api-security-testing-framework/
├── src/
│   ├── main/
│   │   ├── java/org/owasp/astf/
│   │   │   ├── cli/           # ASTFCli.java — picocli entry point
│   │   │   ├── core/          # Scanner, EndpointDiscoveryService, HTTP client
│   │   │   ├── testcases/     # 12 security test cases + TestCaseRegistry
│   │   │   ├── reporting/     # JSON, HTML, SARIF, XML report generators
│   │   │   └── integrations/  # GitHub Actions result processor
│   │   └── resources/
│   │       └── log4j2.xml     # Logging configuration
│   └── test/                  # 229 unit tests across 25 test suites
├── docs/
│   ├── FRAMEWORK_OVERVIEW.md  # Capabilities, all 12 test cases, crAPI results
│   ├── ARCHITECTURE.md        # Component design, data flow, extension guide
│   ├── TROUBLESHOOTING.md     # Logging, common errors, issue templates
│   └── examples/
│       ├── scan-config.yaml   # Full annotated config reference
│       ├── scan-config.json   # JSON equivalent
│       └── quickstart.yaml    # Minimal 3-field config
└── .github/
    ├── workflows/
    │   ├── ci.yml             # Robo-Reviewer — runs tests on every PR
    │   └── release.yml        # Publishes JAR to GitHub Releases on v* tags
    └── ISSUE_TEMPLATE/        # Bug, feature, docs, test-case templates
```

---

## Documentation

| Document | Description |
|---|---|
| [Framework Overview](docs/FRAMEWORK_OVERVIEW.md) | All 12 test cases, crAPI proof of concept, use cases |
| [Architecture](docs/ARCHITECTURE.md) | Component design, data flow, how to add a test case |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Logging config, common errors, issue templates |
| [Full Config Reference](docs/examples/scan-config.yaml) | Every config option with inline comments |
| [Quickstart Config](docs/examples/quickstart.yaml) | Minimal working config |
| [Releases](https://github.com/OWASP/www-project-api-security-testing-framework/releases) | Pre-built JARs for every version |

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**To report a bug:** [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md)
**To request a feature:** [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md)
**To improve a test case:** [Test Case Enhancement template](.github/ISSUE_TEMPLATE/test_case_enhancement.md)
**To improve docs:** [Documentation Improvement template](.github/ISSUE_TEMPLATE/documentation_improvement.md)

To add a new test case, see [Adding New Test Cases](docs/ARCHITECTURE.md#adding-new-test-cases).

### Cutting a Release (maintainers)

```bash
# 1. Ensure main is green (all CI checks pass)
# 2. Tag and push — the release workflow does everything else
git tag v1.1.0-beta
git push origin v1.1.0-beta
```

The `release.yml` workflow will run all 229 tests, build `astf-v1.1.0-beta.jar`,
create a GitHub Release marked as pre-release, and attach the JAR as a downloadable asset.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Contact

- Project Leader: [Govindarajan Lakshmikanthan](https://github.com/GovindarajanL)
- OWASP Project Page: [owasp.org/www-project-api-security-testing-framework](https://owasp.org/www-project-api-security-testing-framework/)
- Slack: `#project-api-security-testing-framework`
