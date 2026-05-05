# OWASP API Security Testing Framework

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/www-project-api-security-testing-framework/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![CI](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-224%20passing-brightgreen.svg)](#)

A comprehensive automated testing framework for detecting API security vulnerabilities based on the **OWASP API Security Top 10 2023**.

---

## Quick Start

### 1. Prerequisites

| Requirement | Version | Why |
|---|---|---|
| **Java** | 21+ | The Scanner core uses Java 21 **virtual threads** for high-concurrency scanning |
| **Maven** | 3.6+ | Build tool |

### 2. Build

```bash
git clone https://github.com/OWASP/www-project-api-security-testing-framework.git
cd www-project-api-security-testing-framework
mvn clean package -DskipTests
```

The runnable fat JAR is produced at:
```
target/api-security-testing-framework-1.0-SNAPSHOT.jar
```

### 3. Run your first scan (copy-paste ready)

**Option A — Inline flags** (quickest):
```bash
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u https://api.example.com \
  --token "YOUR_BEARER_TOKEN" \
  -f HTML -o results.html -v
```

**Option B — Config file** (recommended for repeatable scans):
```bash
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -c docs/examples/scan-config.yaml
```

**Option C — Against OWASP crAPI** (zero-config proof of concept):
```bash
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u http://crapi.apisec.ai \
  -f HTML -o crapi-report.html --timeout 3
# Auto-discovers 832 endpoints, detects 11 vulnerability types
```

Open the HTML report in your browser:
```
# macOS / Linux
open crapi-report.html

# Windows
start crapi-report.html
```

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

For API key authentication instead of a Bearer token:

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
            [--exclude-tests=<ids>] [-f=<format>] [-o=<outputFile>]
            [--password=<password>] [--proxy=<proxyUrl>] [-t=<threads>]
            [--test-cases=<ids>] [--timeout=<minutes>] [--token=<bearerToken>]
            [-u=<targetUrl>] [--username=<username>] [--header=<Key:Value>]...
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
| `--threads` | `-t` | Concurrent threads | `10` |
| `--timeout` | | Scan timeout in minutes | `30` |
| `--test-cases` | | Comma-separated test case IDs to run | all |
| `--exclude-tests` | | Comma-separated test case IDs to skip | none |
| `--no-discovery` | | Disable auto endpoint discovery | false |
| `--verbose` | `-v` | Verbose output | false |
| `--version` | `-V` | Print version | — |
| `--help` | `-h` | Show help | — |

### Exit Codes

| Code | Meaning | CI usage |
|---|---|---|
| `0` | Scan completed — no findings | Pipeline passes |
| `1` | Scan completed — findings detected | Fail pipeline on HIGH/CRITICAL (see CI/CD section) |
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
| `ASTF-API7-2023` | Server-Side Request Forgery | `ServerSideRequestForgeryTestCase` | SSRF via `url`, `webhook`, `redirect`, `callback` parameters in query strings and POST bodies — injects AWS metadata URL |
| `ASTF-API8-2023` | Security Misconfiguration | `SecurityMisconfigurationTestCase` | Missing security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`), verbose error messages, stack traces |
| `ASTF-API9-2023` | Improper Inventory Management | `ImproperInventoryManagementTestCase` | Deprecated API versions (`/v1`, `/v2`), shadow/undocumented endpoints, exposed API docs (`/swagger-ui`, `/graphiql`) |
| `ASTF-API10-2023` | Unsafe Consumption of APIs | `UnsafeConsumptionOfApisTestCase` | Injection via webhook/integration endpoints, open redirect in third-party callback URLs |
| `ASTF-GRAPHQL-2023` | GraphQL Security | `GraphQLSecurityTestCase` | Introspection enabled, field suggestion leakage ("Did you mean…"), query depth attacks (DoS), batch query abuse (rate-limit bypass) |
| `ASTF-GRPC-2023` | gRPC Endpoint Detection | `GrpcEndpointDetectionTestCase` | gRPC service detection via `application/grpc` content-type, server reflection enabled (schema enumeration risk) |

Run only specific test cases:
```bash
# BOLA + Broken Auth only
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u https://api.example.com \
  --test-cases ASTF-API1-2023,ASTF-API2-2023

# Skip GraphQL and gRPC checks
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u https://api.example.com \
  --exclude-tests ASTF-GRAPHQL-2023,ASTF-GRPC-2023
```

---

## Reporting & Interpreting Results

### Output Formats

| Format | Flag | Best for |
|---|---|---|
| **HTML** | `-f HTML` | Human review — renders severity-coloured findings with evidence and remediation |
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
                  meaning no signature validation is performed. Any client can forge
                  a token and impersonate any user.",
  "evidence": "Server returned HTTP 200 when presented with a JWT using 'none' algorithm",
  "recommendation": "Reject tokens with 'alg: none'. In Spring Security, configure
                     NimbusJwtDecoder with an explicit algorithm allowlist.
                     In Node.js (jsonwebtoken), set algorithms: ['HS256']."
}
```

| Field | What it tells you |
|---|---|
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO — prioritise fixes by this |
| `evidence` | The exact HTTP signal that confirmed the vulnerability — include this in your bug report |
| `recommendation` | Framework-specific fix instructions — hand directly to the developer |
| `testCaseId` | Which ASTF check triggered — maps to an OWASP API Top 10 category |
| `endpoint` | The exact method + path — tells you which route to patch |

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

      - name: Build ASTF
        run: mvn --batch-mode --no-transfer-progress package -DskipTests

      - name: Run ASTF scan
        run: |
          java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
            -u ${{ secrets.API_URL }} \
            --token ${{ secrets.API_TOKEN }} \
            -f SARIF -o results.sarif \
            --timeout 10 || EXIT_CODE=$?
          echo "ASTF_EXIT=$EXIT_CODE" >> $GITHUB_ENV

      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        continue-on-error: true

      - name: Fail build on HIGH or CRITICAL findings
        run: |
          if [ "$ASTF_EXIT" = "1" ]; then
            echo "ASTF detected security findings. Review the SARIF report."
            exit 1
          fi
```

### Fail the Build Only on HIGH/CRITICAL

ASTF exits with code `1` whenever any finding is detected. To gate only on HIGH or CRITICAL, post-process the JSON output:

```bash
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u $API_URL --token $TOKEN -f JSON -o results.json

# Fail if any HIGH or CRITICAL findings exist
HIGH_CRIT=$(jq '[.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' results.json)
if [ "$HIGH_CRIT" -gt "0" ]; then
  echo "Build failed: $HIGH_CRIT HIGH/CRITICAL findings detected"
  exit 1
fi
echo "No HIGH or CRITICAL findings. Pipeline passes."
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
│   └── test/                  # 224 unit tests across 25 test suites
├── docs/
│   ├── FRAMEWORK_OVERVIEW.md  # Capabilities, all 12 test cases, crAPI results
│   ├── ARCHITECTURE.md        # Component design, data flow, extension guide
│   ├── TROUBLESHOOTING.md     # Logging, common errors, issue templates
│   └── examples/
│       ├── scan-config.yaml   # Full annotated config reference
│       ├── scan-config.json   # JSON equivalent
│       └── quickstart.yaml    # Minimal 3-field config
└── .github/
    ├── workflows/ci.yml        # Robo-Reviewer CI workflow
    └── ISSUE_TEMPLATE/         # Bug, feature, docs, test-case templates
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

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**To report a bug:** use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md)  
**To request a feature:** use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md)  
**To improve a test case:** use the [Test Case Enhancement template](.github/ISSUE_TEMPLATE/test_case_enhancement.md)

To add a new test case, see the [Adding New Test Cases](docs/ARCHITECTURE.md#adding-new-test-cases) section of the Architecture docs.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Contact

- Project Leader: [Govindarajan Lakshmikanthan](https://github.com/GovindarajanL)
- OWASP Project Page: [owasp.org/www-project-api-security-testing-framework](https://owasp.org/www-project-api-security-testing-framework/)
- Slack: `#project-api-security-testing-framework`
