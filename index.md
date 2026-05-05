---
title: OWASP API Security Testing Framework
layout: col-sidebar
tags: api-security testing automation breaker
level: 2
type: tool
pitch: A comprehensive automated testing framework for detecting API security vulnerabilities based on the OWASP API Security Top 10 2023

---

# OWASP API Security Testing Framework

## Description

The OWASP API Security Testing Framework (ASTF) is a specialized security testing tool designed to automatically detect vulnerabilities in APIs based on the **OWASP API Security Top 10 2023**. It discovers endpoints automatically, runs 12 security test cases covering the full Top 10 plus GraphQL and gRPC, and produces findings in JSON, HTML, SARIF, and XML formats.

**Current release: [v1.0.0-beta](https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest)**

ASTF has been validated against [OWASP crAPI](https://github.com/OWASP/crAPI) — the intentionally vulnerable API — where it auto-discovered 832 endpoints and detected 11 distinct vulnerability types including JWT algorithm weaknesses, missing authentication controls, and improper inventory management.

## Key Features

- **100% OWASP API Security Top 10 2023 coverage** — all 10 categories implemented and tested
- **12 security test cases** — API1 through API10, plus dedicated GraphQL and gRPC checks
- **Auto endpoint discovery** — finds endpoints via OpenAPI/Swagger probing and common path patterns; zero config required for a first scan
- **Multiple auth modes** — Bearer token, API key, Basic auth, custom headers
- **Four output formats** — HTML (human review), JSON (processing), SARIF (GitHub Code Scanning), XML
- **CI/CD ready** — GitHub Actions workflow included; exits with code `1` when findings detected for pipeline gating
- **224 passing unit tests** — fully test-covered implementation
- **Proven on real targets** — validated against OWASP crAPI public demo

## Test Case Coverage

| ID | Vulnerability | What It Detects |
|---|---|---|
| ASTF-API1-2023 | Broken Object Level Authorization | BOLA/IDOR via ID manipulation |
| ASTF-API2-2023 | Broken Authentication | Missing auth, JWT `none` algorithm, expired tokens, 2FA bypass |
| ASTF-API3-2023 | Broken Object Property Level Authorization | Sensitive fields in responses, mass assignment |
| ASTF-API4-2023 | Unrestricted Resource Consumption | Missing rate limiting headers |
| ASTF-API5-2023 | Broken Function Level Authorization | Admin endpoints accessible without privileges |
| ASTF-API6-2023 | Unrestricted Access to Sensitive Flows | Missing bot protection on login/OTP/payment flows |
| ASTF-API7-2023 | Server-Side Request Forgery | SSRF via URL/webhook/redirect parameters |
| ASTF-API8-2023 | Security Misconfiguration | Missing security headers, verbose errors |
| ASTF-API9-2023 | Improper Inventory Management | Deprecated versions, shadow endpoints, exposed docs |
| ASTF-API10-2023 | Unsafe Consumption of APIs | Injection via integration endpoints, open redirect |
| ASTF-GRAPHQL-2023 | GraphQL Security | Introspection, field suggestions, depth attacks, batch abuse |
| ASTF-GRPC-2023 | gRPC Endpoint Detection | Service detection, server reflection enabled |

## Getting Started

**Requirements:** Java 21+

```bash
# Download the latest release
curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v1.0.0-beta.jar

# Run against your API
java -jar astf-v1.0.0-beta.jar -u https://api.example.com --token "YOUR_TOKEN" -f HTML -o report.html

# Try against OWASP crAPI (zero config needed)
java -jar astf-v1.0.0-beta.jar -u http://crapi.apisec.ai -f HTML -o crapi-report.html
```

Or build from source:
```bash
git clone https://github.com/OWASP/www-project-api-security-testing-framework.git
cd www-project-api-security-testing-framework
mvn clean package -DskipTests
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar -u https://api.example.com
```

For full documentation see the [GitHub repository](https://github.com/OWASP/www-project-api-security-testing-framework).

## CI/CD Integration

Add ASTF to your GitHub Actions pipeline to scan on every pull request:

```yaml
- name: Download ASTF
  run: curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v1.0.0-beta.jar

- name: Run security scan
  run: java -jar astf-v1.0.0-beta.jar -u ${{ secrets.API_URL }} --token ${{ secrets.API_TOKEN }} -f SARIF -o results.sarif

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Roadmap

### ✅ Phase 1 — Core Framework (Completed Q2 2025)
- Core scanning engine with virtual thread concurrency
- All 10 OWASP API Security Top 10 2023 test cases
- JSON, HTML, SARIF, XML report generators
- CLI with config file support (YAML/JSON)
- 224 unit tests

### ✅ Phase 2 — Extended Coverage (Completed Q4 2025)
- GraphQL security test case (introspection, field suggestions, depth attacks, batch abuse)
- gRPC endpoint detection stub with server reflection check
- GitHub Actions CI/CD workflow
- Comprehensive documentation (Quick Start, CLI reference, Troubleshooting)
- Validated against OWASP crAPI — 11 vulnerability types detected

### ✅ Phase 3 — Beta Release (Completed Q2 2026)
- Automated release workflow — JAR published to GitHub Releases on version tags
- `v1.0.0-beta` released with pre-built downloadable JAR
- Full OWASP project page update

### 🔜 Phase 4 — Stable Release (Planned)
- OpenAPI/Swagger spec import for precise endpoint targeting
- Plugin system for custom test cases
- Distributed scanning for large API surfaces
- Integration with vulnerability management platforms (Defect Dojo, Jira)

## Getting Involved

The API Security Testing Framework welcomes community contributions:

- **Bug reports** — use the [Bug Report template](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=bug_report.md)
- **Feature requests** — use the [Feature Request template](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=feature_request.md)
- **New test cases** — see the [Architecture docs](https://github.com/OWASP/www-project-api-security-testing-framework/blob/main/docs/ARCHITECTURE.md) for the extension guide
- **Documentation** — use the [Documentation Improvement template](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=documentation_improvement.md)

## Related Projects

- [OWASP API Security Project](https://owasp.org/www-project-api-security/) — The Top 10 standard this framework implements
- [OWASP crAPI](https://github.com/OWASP/crAPI) — Intentionally vulnerable API for testing
- [OWASP ZAP](https://www.zaproxy.org) — Complementary web application scanner

## Licensing

This project is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0.html).

## Project Leaders

- [Govindarajan Lakshmikanthan](mailto:govindarajan.lakshmikanthan@owasp.org) — Project Leader
  - GitHub: [@GovindarajanL](https://github.com/GovindarajanL)
