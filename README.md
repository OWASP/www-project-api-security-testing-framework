# OWASP API Security Testing Framework

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/www-project-api-security-testing-framework/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![CI](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-350%20passing-brightgreen.svg)](#)
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
# Download the latest stable release
curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v2.0.1.jar
```

Or build from source:

```bash
git clone https://github.com/OWASP/www-project-api-security-testing-framework.git
cd www-project-api-security-testing-framework
mvn clean package -DskipTests
# JAR is at: target/api-security-testing-framework-2.0.1.jar
```

### 3. Run your first scan (copy-paste ready)

**Option A — Inline flags** (quickest):
```bash
java -jar astf-v2.0.1.jar \
  -u https://api.example.com \
  --token "YOUR_BEARER_TOKEN" \
  -f HTML -o results.html -v
```

**Option B — Config file** (recommended for repeatable scans):
```bash
java -jar astf-v2.0.1.jar -c docs/examples/scan-config.yaml
```

**Option C — Against OWASP crAPI** (zero-config proof of concept):
```bash
java -jar astf-v2.0.1.jar \
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

Releases are published automatically when a version tag is pushed. The workflow runs all 350 tests, builds the fat JAR, and attaches it to the GitHub Release.

| Tag format | Release type | Example |
|---|---|---|
| `v*-beta` | Pre-release | `v2.0.1-beta` |
| `v*-rc*` | Release candidate | `v2.0.1-rc1` |
| `v*` (no suffix) | Stable release | `v2.0.1` ← current |

**[→ View all releases](https://github.com/OWASP/www-project-api-security-testing-framework/releases)**

The JAR asset on each release is named `astf-<tag>.jar`, e.g. `astf-v2.0.1.jar`. Use this name in your CI pipelines to pin a specific version.

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
| `--secondary-token` | | Bearer token for a **second, distinct** authenticated identity — enables cross-user BOLA testing (see [Testing Guidelines](docs/TESTING_GUIDELINES.md#authorization-testing-methodologies)) | — |
| `--client-cert` | | Path to a PKCS12 (`.p12`/`.pfx`) keystore with a client certificate to present for mutual TLS | — |
| `--client-cert-password` | | Password for `--client-cert` | — |
| `--invalid-client-cert` | | Path to a deliberately invalid/untrusted PKCS12 keystore, used alongside `--client-cert` to test whether the server actually validates client certificates | — |
| `--invalid-client-cert-password` | | Password for `--invalid-client-cert` | — |
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

**Cross-user authorization testing example:**
```bash
java -jar astf.jar -u https://api.example.com \
  --token "$USER_A_TOKEN" --secondary-token "$USER_B_TOKEN"
# Checks whether User B's identity can access/modify objects reachable via User A's token
# without any ID substitution — the strongest form of evidence ASTF produces for BOLA.
```

**Mutual TLS validation example:**
```bash
java -jar astf.jar -u https://api.example.com \
  --client-cert valid-client.p12 --client-cert-password "changeit" \
  --invalid-client-cert untrusted-client.p12 --invalid-client-cert-password "changeit"
# Flags the server if it accepts the untrusted certificate just as readily as the valid one.
```

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
java -jar astf-v2.0.1.jar -u https://api.example.com \
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

100% coverage of the **OWASP API Security Top 10 2023**, plus GraphQL, gRPC, mTLS, LLM, and general injection — **16 test cases** in total. See [Testing Guidelines](docs/TESTING_GUIDELINES.md) for the methodology behind each category, not just what it checks.

| ID | Name | Implementation Class | What It Detects |
|---|---|---|---|
| `ASTF-API1-2023` | Broken Object Level Authorization | `BrokenObjectLevelAuthorizationTestCase` | BOLA/IDOR — numeric/UUID ID substitution, unresolved-template-path resolution, and **cross-user access confirmation** (same URL, two distinct identities via `--secondary-token`, no ID guessing) |
| `ASTF-API2-2023` | Broken Authentication | `BrokenAuthenticationTestCase` | Missing auth, JWT `none` algorithm, `kid` path traversal, RS256→HS256 algorithm confusion (via real JWKS fetch), `jku` header abuse, expired tokens, tokens in URL, username/password enumeration, brute-force lockout, 2FA bypass, insecure session cookies |
| `ASTF-API3-2023` | Broken Object Property Level Authorization | `BrokenObjectPropertyLevelAuthorizationTestCase` | Password/secret fields in responses (excessive data exposure), mass assignment via POST |
| `ASTF-API4-2023` | Unrestricted Resource Consumption | `UnrestrictedResourceConsumptionTestCase` | Missing rate limiting (burst-request test, HTTP 429/423 or body-level rejection signal) on resource-heavy endpoints |
| `ASTF-API5-2023` | Broken Function Level Authorization | `BrokenFunctionLevelAuthorizationTestCase` | Admin endpoints reachable without elevated privileges, HTTP method escalation, and **privilege-tier path substitution** (`/user/...` → `/admin/...` on an otherwise identical request) |
| `ASTF-API6-2023` | Unrestricted Access to Sensitive Flows | `UnrestrictedAccessToSensitiveFlowsTestCase` | Rate limiting and bot protection absent on login, OTP, payment, and password-reset flows |
| `ASTF-API7-2023` | Server-Side Request Forgery | `ServerSideRequestForgeryTestCase` | SSRF via `url`, `webhook`, `redirect`, `callback` parameters — injects cloud metadata endpoint URLs |
| `ASTF-API8-2023` | Security Misconfiguration | `SecurityMisconfigurationTestCase` | Missing security headers, verbose error messages, stack traces in responses |
| `ASTF-API9-2023` | Improper Inventory Management | `ImproperInventoryManagementTestCase` | Deprecated API versions, shadow endpoints, exposed API docs |
| `ASTF-API10-2023` | Unsafe Consumption of APIs | `UnsafeConsumptionOfApisTestCase` | Injection via webhook/integration endpoints, open redirect in callback URLs |
| `ASTF-GRAPHQL-2023` | GraphQL Security | `GraphQLSecurityTestCase` | Introspection, field suggestion leakage, query depth/batch/field-duplication/alias/circular-fragment DoS, resolver injection (SQL/OS-command/XSS/SSRF) across every mutation and query field, GraphiQL/IDE exposure, deny-list bypass via fragments, argument-based auth bypass, login brute-force, stack-trace disclosure |
| `ASTF-GRPC-2023` | gRPC Endpoint Detection | `GrpcEndpointDetectionTestCase` | gRPC service detection over h2c, server reflection enabled (schema enumeration risk), scoped injection testing |
| `ASTF-MTLS-2023` | Mutual TLS Validation | `MutualTlsValidationTestCase` | Whether the server actually validates client certificate trust chains, or accepts any presented certificate |
| `ASTF-LLM-2023` | LLM Prompt Injection | `LlmPromptInjectionTestCase` | Prompt injection against LLM/chatbot-backed endpoints, via a distinctive canary-string instruction |
| `ASTF-INJECTION-2023` | SQL/NoSQL Injection | `SqlNoSqlInjectionTestCase` | General-purpose SQL/NoSQL injection on REST body fields and path parameters (resolved or unresolved), independent of endpoint naming |
| `ASTF-REDOS-2023` | Regular Expression Denial of Service | `RegexDosTestCase` | Catastrophic-backtracking-triggering payloads, detected via response-time comparison against a baseline |

Run only specific test cases:
```bash
java -jar astf-v2.0.1.jar -u https://api.example.com \
  --test-cases ASTF-API1-2023,ASTF-API2-2023

java -jar astf-v2.0.1.jar -u https://api.example.com \
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
          curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v2.0.1.jar

      - name: Run ASTF scan
        run: |
          java -jar astf-v2.0.1.jar \
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
java -jar astf-v2.0.1.jar \
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
│   │   │   ├── testcases/     # 16 security test cases + TestCaseRegistry
│   │   │   ├── reporting/     # JSON, HTML, SARIF, XML report generators
│   │   │   └── integrations/  # GitHub Actions result processor
│   │   └── resources/
│   │       └── log4j2.xml     # Logging configuration
│   └── test/                  # 350 unit tests
├── docs/
│   ├── TESTING_GUIDELINES.md  # Methodology: how to test, interpret results, reduce false positives
│   ├── FRAMEWORK_OVERVIEW.md  # Capabilities, all 16 test cases, live-verification results
│   ├── TRACEABILITY.md        # Documented vulnerabilities vs. actual detections, per target
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
| [Testing Guidelines](docs/TESTING_GUIDELINES.md) | **Start here for methodology** — testing approaches, auth/authz/data-validation/rate-limiting strategies, result interpretation, false-positive reduction, remediation guidance |
| [Framework Overview](docs/FRAMEWORK_OVERVIEW.md) | All 16 test cases, live-verification results against real vulnerable targets, use cases |
| [Traceability Matrix](docs/TRACEABILITY.md) | Every documented vulnerability in VAmPI, crAPI, DVGA, and gRPC Goat, traced against what ASTF actually detects — published misses included, not just hits |
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
git tag v2.0.1
git push origin v2.0.1
```

The `release.yml` workflow will run all 350 tests, build `astf-v2.0.1.jar`, and create a
GitHub Release with the JAR attached as a downloadable asset. A plain `vX.Y.Z` tag (no
`alpha`/`beta`/`rc` suffix) is published as a **stable** release; only tags matching one of
those suffixes are marked as a pre-release — see the [tag format table](#releases) above.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Contact

- Project Leader: [Govindarajan Lakshmikanthan](https://github.com/GovindarajanL)
- OWASP Project Page: [owasp.org/www-project-api-security-testing-framework](https://owasp.org/www-project-api-security-testing-framework/)
- Slack: `#project-api-security-testing-framework`
