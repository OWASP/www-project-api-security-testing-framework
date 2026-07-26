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

### 2. Security Testing — 16 Test Cases

Every discovered endpoint is tested by all 16 active test cases. This represents **100% coverage of the OWASP API Security Top 10 2023**, plus dedicated GraphQL, gRPC, mTLS, LLM, and general-injection checks. See [Testing Guidelines](TESTING_GUIDELINES.md) for the methodology behind each category.

| ID | Name | Class | Detection Logic |
|---|---|---|---|
| `ASTF-API1-2023` | **Broken Object Level Authorization** | `BrokenObjectLevelAuthorizationTestCase` | Manipulates numeric IDs and UUIDs in URL path segments; resolves unresolved OpenAPI path-template placeholders (e.g. `{book_title}`) to a real discovered value first; and — the strongest signal — **cross-user access confirmation**: requests the exact same URL with two distinct identities (`--secondary-token`) and flags it when both succeed with no ID substitution at all |
| `ASTF-API2-2023` | **Broken Authentication** | `BrokenAuthenticationTestCase` | Missing auth, JWT `none` algorithm, JWT `kid` header path traversal, RS256→HS256 algorithm confusion (fetches the real JWKS and reuses the RSA public key as an HMAC secret), `jku` header abuse, expired JWT acceptance, tokens in URL query params, username/password enumeration (differential response comparison), brute-force lockout (8 consecutive failed attempts, checks for 429/423), 2FA bypass with guessable OTPs, insecure session cookies |
| `ASTF-API3-2023` | **Broken Object Property Level Authorization** | `BrokenObjectPropertyLevelAuthorizationTestCase` | Scans GET responses for sensitive field names (`password`, `secret`, `ssn`, `credit_card`); sends POST with extra fields to detect mass assignment |
| `ASTF-API4-2023` | **Unrestricted Resource Consumption** | `UnrestrictedResourceConsumptionTestCase` | Sends a burst of requests and checks for absence of a rate-limit signal (HTTP 429/423, or a body-level rejection message for APIs that signal failure via 200 status) |
| `ASTF-API5-2023` | **Broken Function Level Authorization** | `BrokenFunctionLevelAuthorizationTestCase` | Probes administrative paths (`/admin`, `/internal`, `/manage`, `/superuser`) appended to the base URL; HTTP method escalation (GET succeeds → does PUT/DELETE/PATCH also succeed?); and **privilege-tier path substitution** — swaps a low-privilege path segment (`user`/`customer`/`member`/`public`) for a high-privilege one (`admin`/`staff`/`internal`/`management`/`superuser`) on an already-known, specific endpoint and replays the identical request with the identical token |
| `ASTF-API6-2023` | **Unrestricted Access to Sensitive Flows** | `UnrestrictedAccessToSensitiveFlowsTestCase` | Identifies sensitive flow paths (`/login`, `/otp`, `/payment`, `/reset-password`) and checks for rate-limiting and bot-protection indicators |
| `ASTF-API7-2023` | **Server-Side Request Forgery** | `ServerSideRequestForgeryTestCase` | Injects cloud metadata endpoint URLs into `url`, `webhook`, `redirect`, and `callback` parameters in both query strings and POST bodies |
| `ASTF-API8-2023` | **Security Misconfiguration** | `SecurityMisconfigurationTestCase` | Checks for absence of standard security headers; checks for stack traces and verbose error messages in 4xx/5xx responses |
| `ASTF-API9-2023` | **Improper Inventory Management** | `ImproperInventoryManagementTestCase` | Probes legacy versioned paths, shadow/non-production paths, and exposed API documentation endpoints |
| `ASTF-API10-2023` | **Unsafe Consumption of APIs** | `UnsafeConsumptionOfApisTestCase` | Sends injection payloads to webhook/integration endpoints; checks for open redirect via redirect parameters |
| `ASTF-GRAPHQL-2023` | **GraphQL Security** | `GraphQLSecurityTestCase` | Introspection exposure, field-suggestion leakage, query-depth/batch/field-duplication/alias-based/circular-fragment DoS, resolver injection (SQL/OS-command/XSS/SSRF) across **every** discovered mutation and query field with a string argument, GraphiQL/IDE exposure (with cookie-bypass variant), deny-list bypass via fragment wrapping, argument-based auth bypass, login-mutation brute-force, stack-trace/debug-error disclosure |
| `ASTF-GRPC-2023` | **gRPC Endpoint Detection** | `GrpcEndpointDetectionTestCase` | Detects gRPC services over h2c (HTTP/2 cleartext), checks whether server reflection is active (schema enumeration risk), scoped injection testing |
| `ASTF-MTLS-2023` | **Mutual TLS Validation** | `MutualTlsValidationTestCase` | Presents both a valid client certificate (`--client-cert`) and a deliberately invalid one (`--invalid-client-cert`); flags the server if it accepts both equally, indicating it isn't actually validating the trust chain |
| `ASTF-LLM-2023` | **LLM Prompt Injection** | `LlmPromptInjectionTestCase` | Heuristically tests LLM/chatbot-backed endpoints for prompt injection by submitting instructions asking the model to emit a distinctive canary string |
| `ASTF-INJECTION-2023` | **SQL/NoSQL Injection** | `SqlNoSqlInjectionTestCase` | General-purpose SQL/NoSQL injection testing on ordinary REST body fields and path parameters (resolved or unresolved templates), independent of HTTP method or endpoint naming — complements the narrower, path-keyword-gated injection check in `ASTF-API10-2023` |
| `ASTF-REDOS-2023` | **Regular Expression Denial of Service** | `RegexDosTestCase` | Sends catastrophic-backtracking-triggering payloads and compares response time against a per-endpoint baseline |

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
- JWT `none` algorithm acceptance, `kid` path traversal, RS256→HS256 algorithm confusion, `jku` header abuse
- Expired JWT token acceptance
- Tokens exposed in URL query parameters
- Username/password enumeration and brute-force lockout resistance
- 2FA/MFA bypass via guessable OTP codes (000000, 123456, etc.)
- Session cookie security flags (HttpOnly, Secure, SameSite)
- Admin endpoint access without elevated privileges, plus **privilege-tier path substitution** (an admin-tier sibling of an already-known endpoint)
- **Cross-user authorization testing** — configure a second identity with `--secondary-token` and ASTF checks whether it can access or modify objects reachable via the primary identity's token, on the exact same URL with no ID guessing. This is the strongest evidence class ASTF produces for BOLA, and has confirmed real account-takeover-class vulnerabilities in live testing.
- **Mutual TLS validation** — presents both a valid and a deliberately invalid client certificate to check whether the server actually verifies the trust chain

### GraphQL-Specific Testing

- Introspection query detection — reveals full schema to attackers
- Field suggestion leakage — "Did you mean…" hints enable schema enumeration even without introspection
- Denial of service — query depth, batch queries, field duplication, alias-based, and circular-fragment attacks
- Resolver-level injection (SQL/OS-command/XSS/SSRF) across every discovered mutation and query field with a string argument
- GraphiQL/IDE exposure (with a cookie-bypass variant), deny-list bypass via fragment wrapping, argument-based auth bypass, login-mutation brute-force, stack-trace/debug-error disclosure

### gRPC Detection

ASTF probes for `Content-Type: application/grpc` responses over h2c (HTTP/2 cleartext) to identify gRPC services, then checks whether the gRPC server reflection service is active (the gRPC equivalent of GraphQL introspection). Full gRPC exploit testing requires `.proto` schema files and is flagged for manual follow-up.

### General Injection & Denial of Service

- SQL/NoSQL injection on ordinary REST body fields and path parameters, independent of HTTP method or endpoint naming — detected by matching real database error signatures (SQLAlchemy, SQLite, PostgreSQL, MySQL, Hibernate, Sequelize, and others), not by payload echo alone
- MongoDB-style NoSQL operator injection (`{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`) for auth-bypass and query-manipulation
- Regular Expression Denial of Service (ReDoS) via catastrophic-backtracking payloads, detected by response-time comparison against a baseline

### LLM/Chatbot Testing

Heuristically tests LLM/chatbot-backed endpoints for prompt injection by submitting an instruction asking the model to emit a distinctive canary string in its response — a model-agnostic way to detect that user input is influencing the system prompt's intended behavior without needing to spend real API credits on a full jailbreak attempt.

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

*(This table is from an early, unauthenticated pass — before cross-user authorization testing, mTLS, LLM, general injection, ReDoS, and the GraphQL resolver-injection/DoS/auxiliary checks existed.)*

### Newer live-verified findings

Later rounds of live testing — against VAmPI, crAPI, and DVGA (Damn Vulnerable GraphQL Application), with the fixes tracked back to each target's own documented vulnerability list — confirmed several vulnerabilities end-to-end on the actual built JAR, not just in unit tests:

- **Real account takeover** via BOLA cross-user testing: a secondary identity changed a primary identity's password, confirmed by logging in with the new password afterward.
- **Real privilege escalation** via BFLA privilege-tier path substitution against the public crAPI demo: a non-admin token succeeded on an admin-tier sibling endpoint that performed no role check at all.
- **GraphQL resolver injection** across multiple mutations and query fields on DVGA, plus alias-based and circular-fragment denial-of-service.

Full details, including exact commands and response evidence, are in the merged pull requests — see [PR #104](https://github.com/OWASP/www-project-api-security-testing-framework/pull/104) and its linked issues (#95–#102) for the most recent round.

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
- **Test Cases** — 16 modular implementations of the `TestCase` interface
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
