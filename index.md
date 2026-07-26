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

The OWASP API Security Testing Framework (ASTF) is a specialized security testing tool designed to automatically detect vulnerabilities in APIs based on the **OWASP API Security Top 10 2023**. It discovers endpoints automatically, runs 16 security test cases covering the full Top 10 plus GraphQL, gRPC, mutual TLS, LLM/chatbot, and general injection testing, and produces findings in JSON, HTML, SARIF, and XML formats.

**Current release: [v2.0.0](https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest)**

ASTF has been validated against real, intentionally-vulnerable API targets — [OWASP crAPI](https://github.com/OWASP/crAPI), [VAmPI](https://github.com/erev0s/VAmPI), and [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) — with findings live-verified against the actual running applications, not just unit tests. That verification confirmed real exploitable conditions: a genuine cross-user account takeover (one identity changing another's password with no ownership check) and a genuine privilege escalation (a non-admin token succeeding on an unprotected admin-tier sibling endpoint) against the public crAPI demo, among others.

## Key Features

- **100% OWASP API Security Top 10 2023 coverage** — all 10 categories implemented and tested
- **16 security test cases** — API1 through API10, plus GraphQL, gRPC, mutual TLS, LLM prompt injection, general SQL/NoSQL injection, and ReDoS
- **Cross-user authorization testing** — provide two distinct authenticated identities and ASTF checks whether one can access or modify the other's objects on the identical URL, with no ID guessing involved. This is the strongest evidence class the framework produces, and it has confirmed real account-takeover-class vulnerabilities in live testing.
- **Auto endpoint discovery** — finds endpoints via OpenAPI/Swagger probing and common path patterns; zero config required for a first scan
- **Multiple auth modes** — Bearer token (including a second, distinct identity for cross-user testing), API key, Basic auth, mutual TLS client certificates, custom headers
- **Four output formats** — HTML (human review), JSON (processing), SARIF (GitHub Code Scanning), XML
- **CI/CD ready** — GitHub Actions workflow included; exits with code `1` when findings detected for pipeline gating
- **350 passing unit tests** — fully test-covered implementation
- **Proven on real targets, with an honest scorecard** — validated against OWASP crAPI, VAmPI, and DVGA, with a public traceability matrix showing exactly what is and isn't detected against each target's own documented vulnerability list, not just an unqualified "100% coverage" claim

## Test Case Coverage

| ID | Vulnerability | What It Detects |
|---|---|---|
| ASTF-API1-2023 | Broken Object Level Authorization | BOLA/IDOR via ID manipulation, plus cross-user access confirmation with two distinct identities |
| ASTF-API2-2023 | Broken Authentication | Missing auth, JWT `none`/`kid`-traversal/algorithm-confusion/`jku` attacks, username enumeration, brute-force lockout, 2FA bypass |
| ASTF-API3-2023 | Broken Object Property Level Authorization | Sensitive fields in responses, mass assignment |
| ASTF-API4-2023 | Unrestricted Resource Consumption | Missing rate limiting (burst-request test) |
| ASTF-API5-2023 | Broken Function Level Authorization | Admin endpoints accessible without privileges, HTTP method escalation, and privilege-tier path substitution (e.g. `/user/...` → `/admin/...` on an otherwise identical request) |
| ASTF-API6-2023 | Unrestricted Access to Sensitive Flows | Missing bot protection on login/OTP/payment flows |
| ASTF-API7-2023 | Server-Side Request Forgery | SSRF via URL/webhook/redirect parameters |
| ASTF-API8-2023 | Security Misconfiguration | Missing security headers, verbose errors |
| ASTF-API9-2023 | Improper Inventory Management | Deprecated versions, shadow endpoints, exposed docs |
| ASTF-API10-2023 | Unsafe Consumption of APIs | Injection via integration endpoints, open redirect |
| ASTF-GRAPHQL-2023 | GraphQL Security | Introspection, field suggestions, 5 denial-of-service variants, resolver injection across every mutation/query field, GraphiQL exposure, deny-list bypass, auth bypass, brute-force, stack-trace disclosure |
| ASTF-GRPC-2023 | gRPC Endpoint Detection | Service detection over h2c, server reflection enabled, scoped injection testing |
| ASTF-MTLS-2023 | Mutual TLS Validation | Whether the server actually validates client certificate trust chains |
| ASTF-LLM-2023 | LLM Prompt Injection | Prompt injection against LLM/chatbot-backed endpoints |
| ASTF-INJECTION-2023 | SQL/NoSQL Injection | General-purpose SQL/NoSQL injection on REST body fields and path parameters |
| ASTF-REDOS-2023 | Regular Expression Denial of Service | Catastrophic-backtracking payloads, detected via response-time baseline comparison |

## Getting Started

**Requirements:** Java 21+

```bash
# Download the latest release
curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v2.0.0.jar

# Run against your API
java -jar astf-v2.0.0.jar -u https://api.example.com --token "YOUR_TOKEN" -f HTML -o report.html

# Try against OWASP crAPI (zero config needed)
java -jar astf-v2.0.0.jar -u http://crapi.apisec.ai -f HTML -o crapi-report.html
```

Or build from source:
```bash
git clone https://github.com/OWASP/www-project-api-security-testing-framework.git
cd www-project-api-security-testing-framework
mvn clean package -DskipTests
java -jar target/api-security-testing-framework-2.0.0.jar -u https://api.example.com
```

For methodology — what to test, how to interpret results, how to avoid false positives — see the [Testing Guidelines](https://github.com/OWASP/www-project-api-security-testing-framework/blob/main/docs/TESTING_GUIDELINES.md). For full documentation see the [GitHub repository](https://github.com/OWASP/www-project-api-security-testing-framework).

## CI/CD Integration

Add ASTF to your GitHub Actions pipeline to scan on every pull request:

```yaml
- name: Download ASTF
  run: curl -LO https://github.com/OWASP/www-project-api-security-testing-framework/releases/latest/download/astf-v2.0.0.jar

- name: Run security scan
  run: java -jar astf-v2.0.0.jar -u ${{ secrets.API_URL }} --token ${{ secrets.API_TOKEN }} -f SARIF -o results.sarif

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
- 229 unit tests

### ✅ Phase 2 — Extended Coverage (Completed Q4 2025)
- GraphQL security test case (introspection, field suggestions, depth attacks, batch abuse)
- gRPC endpoint detection stub with server reflection check
- GitHub Actions CI/CD workflow
- Comprehensive documentation (Quick Start, CLI reference, Troubleshooting)
- Validated against OWASP crAPI — 11 vulnerability types detected

### ✅ Phase 3 — Beta Release (Completed Q2 2026)
- Automated release workflow — JAR published to GitHub Releases on version tags
- `v1.0.0` released with pre-built downloadable JAR

### ✅ Phase 4 — Depth & Real-World Verification (Completed)
- Cross-user authorization testing — a second identity (`--secondary-token`) checked against the first for BOLA, the strongest evidence class the framework produces
- Broken Function Level Authorization: HTTP method escalation and privilege-tier path substitution (`/user/...` → `/admin/...`)
- JWT attack depth: `kid` path traversal, RS256→HS256 algorithm confusion, `jku` header abuse, username enumeration, brute-force lockout detection
- Mutual TLS client-certificate validation testing
- LLM/chatbot prompt injection testing
- General-purpose SQL/NoSQL injection and Regular Expression Denial of Service (ReDoS) test cases
- GraphQL depth: resolver injection across every mutation/query field (not just the first few), 3 additional denial-of-service variants, GraphiQL/IDE exposure, deny-list bypass, argument-based auth bypass, login brute-force, stack-trace disclosure
- Live verification against real running vulnerable applications (crAPI, VAmPI, DVGA) with a published traceability matrix tracing every finding back to each target's own documented vulnerability list
- Comprehensive [Testing Guidelines](https://github.com/OWASP/www-project-api-security-testing-framework/blob/main/docs/TESTING_GUIDELINES.md) covering methodology, result interpretation, and false-positive reduction

### ✅ Phase 5 — v2.0.0 Stable Release (Completed)
- Version bumped to 2.0.0, reflecting the growth from 1 to 16 test cases, cross-user
  authorization testing, mutual TLS/LLM/general-injection/ReDoS coverage, GraphQL depth,
  and live-verified findings against real vulnerable applications since v1.0.0
- Comprehensive Testing Guidelines and a full documentation refresh

### 🔜 Phase 6 — Real-World Pen-Testing Utility (Planned)
- **Multi-step business-logic flow testing** — chained requests where a vulnerable endpoint
  is only reachable via a value returned by an earlier call (e.g. crAPI's mechanic-report
  BOLA, only discoverable through a link embedded in a prior response)
- **Plugin system for custom test cases** — let the community publish and share their own
  checks without needing a core-repo review cycle for every addition
- OpenAPI/Swagger and GraphQL SDL spec import for precise, guess-free endpoint/schema
  targeting instead of pattern-guessed discovery
- Automated login-flow support — configure a credential-submission sequence once instead of
  pasting a pre-fetched token into every run
- Findings baseline/suppression — accept a known, risk-accepted finding once instead of
  re-flagging it on every CI run
- `--dry-run`/safe-mode for state-changing checks — live testing has already proven the
  cross-user BOLA check can cause a real password change or resource deletion, not just a
  2xx response; anyone running this against anything sensitive needs an explicit control
- Distributed scanning for large API surfaces, and integration with vulnerability management
  platforms (Defect Dojo, Jira) — both scoped as thin, optional integrations rather than new
  subsystems, to keep the project a security-testing engine rather than a security-operations
  platform

## Getting Involved

The API Security Testing Framework welcomes community contributions:

- **Bug reports** — use the [Bug Report template](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=bug_report.md)
- **Feature requests** — use the [Feature Request template](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=feature_request.md)
- **New test cases** — see the [Architecture docs](https://github.com/OWASP/www-project-api-security-testing-framework/blob/main/docs/ARCHITECTURE.md) for the extension guide
- **Documentation** — use the [Documentation Improvement template](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=documentation_improvement.md)

## Related Projects

- [OWASP API Security Project](https://owasp.org/www-project-api-security/) — The Top 10 standard this framework implements
- [OWASP crAPI](https://github.com/OWASP/crAPI) — Intentionally vulnerable API used for live verification
- [VAmPI](https://github.com/erev0s/VAmPI) — Intentionally vulnerable API used for live verification
- [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) — Intentionally vulnerable GraphQL application used for live verification
- [OWASP ZAP](https://www.zaproxy.org) — Complementary web application scanner

## Licensing

This project is licensed under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0.html).

## Project Leaders

- [Govindarajan Lakshmikanthan](mailto:govindarajan.lakshmikanthan@owasp.org) — Project Leader
  - GitHub: [@GovindarajanL](https://github.com/GovindarajanL)
