# OWASP API Security Testing Framework

[![OWASP Incubator](https://img.shields.io/badge/owasp-incubator-blue.svg)](https://owasp.org/www-project-api-security-testing-framework/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![CI](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/OWASP/www-project-api-security-testing-framework/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-224%20passing-brightgreen.svg)](#)

A comprehensive automated testing framework for detecting API security vulnerabilities based on the **OWASP API Security Top 10 2023**.

## Overview

The OWASP API Security Testing Framework (ASTF) helps security professionals and developers identify vulnerabilities in their APIs through automated testing. It discovers endpoints automatically, runs 12 security test cases covering the full OWASP API Security Top 10 2023 plus GraphQL and gRPC, and produces findings in JSON, HTML, SARIF, and XML formats.

**Proven against [OWASP crAPI](https://github.com/OWASP/crAPI)** — the framework detected 11 distinct vulnerability types across 832 auto-discovered endpoints including JWT `none` algorithm acceptance, missing authentication controls, and deprecated API versions.

## Features

- Automated detection of all **OWASP API Security Top 10 2023** vulnerabilities
- **12 test cases** — API1 through API10, plus dedicated GraphQL and gRPC checks
- Auto-discovery of endpoints (OpenAPI/Swagger, common path patterns, path traversal)
- Support for REST, GraphQL, and gRPC APIs
- Multiple auth modes: Bearer token, API key, Basic auth, custom headers
- Output formats: **JSON, HTML, SARIF, XML**
- CI/CD integration with GitHub Actions and SARIF upload to Code Scanning
- Config-file driven scans (YAML or JSON)
- 224 passing unit tests

## Getting Started

### Prerequisites

- Java 21 or higher
- Maven 3.6+

### Installation

```bash
git clone https://github.com/OWASP/www-project-api-security-testing-framework.git
cd www-project-api-security-testing-framework
mvn clean package -DskipTests
```

The fat JAR is built at `target/api-security-testing-framework-1.0-SNAPSHOT.jar`.

### Quick Start

```bash
# Scan with auto-discovery (no auth)
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u https://api.example.com

# Scan with a Bearer token, verbose output, JSON report
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u https://api.example.com \
  --token "eyJhbGci..." \
  -f JSON -o results.json \
  -v

# Scan using a config file
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -c docs/examples/scan-config.yaml
```

## CLI Reference

```
Usage: astf [-hvV] [--no-discovery] [--api-key=<apiKey>]
            [--api-key-header=<apiKeyHeader>] [-c=<configFile>]
            [--exclude-tests=<disabledTestCases>] [-f=<format>]
            [-o=<outputFile>] [--password=<password>] [--proxy=<proxyUrl>]
            [-t=<threads>] [--test-cases=<enabledTestCases>]
            [--timeout=<timeoutMinutes>] [--token=<bearerToken>]
            [-u=<targetUrl>] [--username=<username>] [--header=<headers>]...
```

| Flag | Short | Description | Default |
|---|---|---|---|
| `--url` | `-u` | Target API base URL | — |
| `--config` | `-c` | Path to YAML/JSON config file | — |
| `--format` | `-f` | Output format: `JSON`, `HTML`, `SARIF`, `XML` | `JSON` |
| `--output` | `-o` | Output file path | stdout |
| `--token` | | Bearer token (sets `Authorization: Bearer …`) | — |
| `--api-key` | | API key value | — |
| `--api-key-header` | | Header name for API key | `X-API-Key` |
| `--username` | | Basic auth username | — |
| `--password` | | Basic auth password | — |
| `--header` | | Extra header as `Key:Value` (repeatable) | — |
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

| Code | Meaning |
|---|---|
| `0` | Scan completed — no findings |
| `1` | Scan completed — findings detected |
| `2` | Scan error (bad config, network failure, etc.) |

## Test Cases

| ID | Name | OWASP Category |
|---|---|---|
| `ASTF-API1-2023` | Broken Object Level Authorization | API1:2023 |
| `ASTF-API2-2023` | Broken Authentication | API2:2023 |
| `ASTF-API3-2023` | Broken Object Property Level Authorization | API3:2023 |
| `ASTF-API4-2023` | Unrestricted Resource Consumption | API4:2023 |
| `ASTF-API5-2023` | Broken Function Level Authorization | API5:2023 |
| `ASTF-API6-2023` | Unrestricted Access to Sensitive Flows | API6:2023 |
| `ASTF-API7-2023` | Server-Side Request Forgery | API7:2023 |
| `ASTF-API8-2023` | Security Misconfiguration | API8:2023 |
| `ASTF-API9-2023` | Improper Inventory Management | API9:2023 |
| `ASTF-API10-2023` | Unsafe Consumption of APIs | API10:2023 |
| `ASTF-GRAPHQL-2023` | GraphQL Security | API3/4/8:2023 |
| `ASTF-GRPC-2023` | gRPC Endpoint Detection | API8/9:2023 |

Run specific test cases:
```bash
# Only BOLA and Broken Auth
java -jar astf.jar -u https://api.example.com \
  --test-cases ASTF-API1-2023,ASTF-API2-2023

# Skip GraphQL and gRPC checks
java -jar astf.jar -u https://api.example.com \
  --exclude-tests ASTF-GRAPHQL-2023,ASTF-GRPC-2023
```

## Configuration File

Scans can be fully described in a YAML or JSON config file passed with `-c`:

```yaml
# docs/examples/quickstart.yaml
target:
  url: "https://api.example.com"

auth:
  bearerToken: "YOUR_JWT_HERE"

output:
  format: "HTML"
  file: "results.html"
```

See [`docs/examples/scan-config.yaml`](docs/examples/scan-config.yaml) for the full annotated reference covering all options (proxy, custom headers, test selection, threading, rate limiting).

## Usage Examples

### Scan with API key authentication

```bash
java -jar astf.jar -u https://api.example.com \
  --api-key "sk-abc123" \
  --api-key-header "X-API-Key" \
  -f HTML -o report.html
```

### Scan a GraphQL API

```bash
java -jar astf.jar -u https://api.example.com/graphql \
  --token "YOUR_TOKEN" \
  --test-cases ASTF-GRAPHQL-2023 \
  -f JSON -o graphql-findings.json
```

### Generate SARIF for GitHub Code Scanning

```bash
java -jar astf.jar -u https://api.example.com \
  --token "$API_TOKEN" \
  -f SARIF -o results.sarif
```

### Prove against OWASP crAPI (intentionally vulnerable API)

```bash
java -jar astf.jar -u http://crapi.apisec.ai \
  -f HTML -o crapi-report.html --timeout 3
# Detected 11 vulnerability types across 832 auto-discovered endpoints
```

## CI/CD Integration

The repository ships with a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs on every pull request:

```yaml
name: Robo-Reviewer (CI)
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v3
        with:
          java-version: '21'
          distribution: 'temurin'
      - run: mvn test
```

To use ASTF as a scanner in your own pipeline, add a step after building:

```yaml
- name: Run ASTF Security Scan
  run: |
    java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
      -u ${{ secrets.API_URL }} \
      --token ${{ secrets.API_TOKEN }} \
      -f SARIF -o results.sarif || true

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Project Structure

```
www-project-api-security-testing-framework/
├── src/
│   ├── main/java/org/owasp/astf/
│   │   ├── cli/           # CLI entry point (ASTFCli.java)
│   │   ├── core/          # Scanner, EndpointDiscovery, HTTP client
│   │   ├── testcases/     # 12 security test cases + registry
│   │   ├── reporting/     # JSON, HTML, SARIF, XML generators
│   │   └── integrations/  # GitHub Actions result processor
│   └── test/              # 224 unit tests
├── docs/
│   ├── FRAMEWORK_OVERVIEW.md
│   ├── ARCHITECTURE.md
│   └── examples/
│       ├── scan-config.yaml   # Full annotated config reference
│       ├── scan-config.json   # JSON equivalent
│       └── quickstart.yaml    # Minimal 3-line config
└── .github/workflows/ci.yml   # Robo-Reviewer CI workflow
```

## Documentation

| Document | Description |
|---|---|
| [Framework Overview](docs/FRAMEWORK_OVERVIEW.md) | Capabilities, test coverage, use cases |
| [Architecture](docs/ARCHITECTURE.md) | Component design, data flow, extension guide |
| [Full Config Reference](docs/examples/scan-config.yaml) | Every config option annotated |
| [Quickstart Config](docs/examples/quickstart.yaml) | Minimal working config |

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

To add a new test case:
1. Implement the `TestCase` interface in `src/main/java/org/owasp/astf/testcases/`
2. Register it in `TestCaseRegistry.registerDefaultTestCases()`
3. Add unit tests (see existing `*TestCaseTest.java` files for patterns)

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Contact

- Project Leader: [Govindarajan Lakshmikanthan](https://github.com/GovindarajanL)
- OWASP Project Page: [owasp.org/www-project-api-security-testing-framework](https://owasp.org/www-project-api-security-testing-framework/)
- Slack: `#project-api-security-testing-framework`
