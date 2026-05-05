# OWASP API Security Testing Framework — Overview

## What This Framework Does

The OWASP API Security Testing Framework (ASTF) is a comprehensive tool designed to identify security vulnerabilities in APIs based on the **OWASP API Security Top 10 2023**. Unlike traditional security tools, ASTF specifically focuses on API-specific vulnerabilities that are often missed by general-purpose scanners.

ASTF has been validated against [OWASP crAPI](https://github.com/OWASP/crAPI) — an intentionally vulnerable API — where it auto-discovered 832 endpoints and detected 11 distinct vulnerability types including JWT algorithm weaknesses, missing authentication controls, and improper inventory management.

## How It Works

The framework operates using a black-box testing approach:

### 1. Endpoint Discovery

Automatically discovers API endpoints through:
- OpenAPI/Swagger specification parsing (`/swagger.json`, `/api-docs`, `/openapi.json`, etc.)
- Common endpoint pattern probing (REST resource paths, versioned paths)
- Intelligent path traversal across `/api/v1/`, `/api/v2/`, `/rest/`, `/service/` prefixes
- Manual endpoint specification via config file

Discovery can be disabled with `--no-discovery` when endpoints are known.

### 2. Security Testing — 12 Test Cases

Every discovered endpoint is tested by all 12 active test cases:

| ID | Name | What It Detects |
|---|---|---|
| `ASTF-API1-2023` | **Broken Object Level Authorization** | BOLA/IDOR — accessing other users' resources by manipulating IDs |
| `ASTF-API2-2023` | **Broken Authentication** | Missing auth controls, JWT `none` algorithm, expired token acceptance, tokens in URLs, 2FA bypass |
| `ASTF-API3-2023` | **Broken Object Property Level Authorization** | Excessive data exposure (password/secret fields), mass assignment via POST |
| `ASTF-API4-2023` | **Unrestricted Resource Consumption** | Missing rate limiting headers, no request throttling |
| `ASTF-API5-2023` | **Broken Function Level Authorization** | Admin endpoints accessible without elevated privileges |
| `ASTF-API6-2023` | **Unrestricted Access to Sensitive Flows** | Rate-limit and bot-protection missing on login, payment, OTP flows |
| `ASTF-API7-2023` | **Server-Side Request Forgery** | SSRF via URL parameters and POST body fields (`url`, `webhook`, `redirect`, etc.) |
| `ASTF-API8-2023` | **Security Misconfiguration** | Missing security headers, verbose error messages, CORS misconfiguration |
| `ASTF-API9-2023` | **Improper Inventory Management** | Deprecated API versions (`/v1`, `/v2`), shadow/undocumented endpoints, exposed API docs |
| `ASTF-API10-2023` | **Unsafe Consumption of APIs** | Injection via webhook/integration endpoints, open redirect |
| `ASTF-GRAPHQL-2023` | **GraphQL Security** | Introspection enabled, field suggestion leakage, query depth attacks, batch query abuse |
| `ASTF-GRPC-2023` | **gRPC Endpoint Detection** | gRPC service detection, server reflection enabled (schema enumeration risk) |

### 3. Vulnerability Reporting

Produces detailed findings including:
- **Severity classification** — CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Vulnerability description** — what is wrong and why it matters
- **Evidence** — exact HTTP response details that triggered the finding
- **Remediation guidance** — specific fix instructions per vulnerability type
- **OWASP mapping** — which API Security Top 10 category applies

Output formats: **JSON** (default), **HTML** (human-readable), **SARIF** (GitHub Code Scanning), **XML**.

## Key Capabilities

### Dynamic API Testing

- Tests live API endpoints with no source code access needed
- Detects vulnerabilities through intelligent request manipulation
- Discovers endpoints automatically — zero config required for a first scan

### Authentication & Authorization Testing

- No-auth access control checks (missing authentication)
- JWT `none` algorithm acceptance
- Expired JWT token acceptance
- Tokens exposed in URL query parameters
- 2FA/MFA bypass via guessable OTP codes (000000, 123456, etc.)
- Session cookie security flags (HttpOnly, Secure, SameSite)
- Admin endpoint access without elevated privileges

### GraphQL-Specific Testing

- Introspection query detection — reveals full schema to attackers
- Field suggestion leakage — "Did you mean…" hints enable schema enumeration even without introspection
- Query depth attack — deeply nested queries exhaust server resources (DoS)
- Batch query abuse — arrays of operations bypass per-request rate limits

### gRPC Detection

ASTF probes for `Content-Type: application/grpc` responses to identify gRPC services, then checks whether the gRPC server reflection service is active (the gRPC equivalent of GraphQL introspection). Full gRPC exploit testing requires `.proto` schema files and is flagged for manual follow-up.

### Integration Capabilities

- GitHub Actions workflow included (`.github/workflows/ci.yml`)
- SARIF output for GitHub Code Scanning dashboards
- HTML reports for stakeholders and audit evidence
- CLI and config-file driven — scriptable in any CI system
- Exit code `1` when findings exist — enables pipeline gating

## Validated Results — OWASP crAPI

Running ASTF against the public OWASP crAPI demo (`http://crapi.apisec.ai`) with no authentication produced:

| Severity | Finding | Endpoints |
|---|---|---|
| CRITICAL | JWT `none` Algorithm Accepted | 304 |
| CRITICAL | Administrative Endpoint Accessible Without Authorization | 17,067 |
| HIGH | Injection Vulnerability in API Integration Endpoint | 94 |
| HIGH | Expired JWT Token Accepted | 324 |
| HIGH | Missing Authentication Controls | 276 |
| HIGH | Shadow/Non-Production API Endpoint Accessible | 1,568 |
| MEDIUM | Missing Rate Limiting | 234 |
| MEDIUM | Authentication Endpoint Requires Manual Review | 16 |
| MEDIUM | Deprecated API Version Still Accessible | 521 |
| MEDIUM | Sensitive Business Flow Missing Bot Protection | 43 |
| MEDIUM | Missing Security Response Headers | 648 |

Command used:
```bash
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar \
  -u http://crapi.apisec.ai -f HTML -o crapi-report.html --timeout 3
```

## Use Cases

### Development Teams

- Test APIs during development before they reach staging
- Integrate into pull-request CI pipelines as an automated reviewer
- Validate security controls before production deployment

### Security Teams

- Assess API security posture across multiple services
- Validate vendor API security with zero source code access
- Generate SARIF evidence for security dashboards and compliance

### DevSecOps

- Automate API security scanning in GitHub Actions / Jenkins / GitLab CI
- Gate deployments on security findings using exit code `1`
- Track vulnerability trends over time with consistent tooling

## Technical Architecture

The framework is built on a modular Java 21 architecture:

- **Core Engine** — Scanner, EndpointDiscoveryService, virtual-thread executor
- **HTTP Client** — OkHttp 4.12 with configurable auth, proxy, retry
- **Test Cases** — 12 modular implementations of the `TestCase` interface
- **Reporting Engine** — JSON, HTML, SARIF, XML generators
- **CLI Interface** — picocli-based with 20+ flags and config file support
- **Integrations** — GitHub Actions SARIF result processor

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full component design and extension guide.

## Intended Audience

The ASTF is designed for:

- Security engineers performing API security assessments
- API developers wanting to catch vulnerabilities before production
- DevOps/DevSecOps engineers integrating security into CI/CD pipelines
- Security consultants validating third-party API security
- Quality assurance testers adding security checks to test suites

No deep security expertise is required to run basic scans; security knowledge helps interpret results and prioritise remediation.
