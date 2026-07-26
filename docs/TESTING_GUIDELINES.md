# API Security Testing Guidelines

This guide answers the question ASTF's [issue #24](https://github.com/OWASP/www-project-api-security-testing-framework/issues/24) was opened for: *how do I actually run an effective API security assessment, not just invoke the tool?* Every technique below is mapped to a real ASTF flag, test case ID, or `Finding` field — nothing here is generic theory you can't act on immediately.

If you only want CLI syntax, see the [README](../README.md#cli-reference). This document is about methodology: what to run, in what order, how to read what comes back, and how to avoid both false confidence and false alarms.

## Contents

- [Testing Approaches: Black-Box vs. Grey-Box](#testing-approaches-black-box-vs-grey-box)
- [Planning an Engagement](#planning-an-engagement)
- [Authentication Testing Strategies](#authentication-testing-strategies)
- [Authorization Testing Methodologies](#authorization-testing-methodologies)
- [Data Validation Testing Techniques](#data-validation-testing-techniques)
- [Rate Limiting Test Approaches](#rate-limiting-test-approaches)
- [GraphQL-Specific Methodology](#graphql-specific-methodology)
- [gRPC-Specific Methodology](#grpc-specific-methodology)
- [Result Interpretation & False-Positive Reduction](#result-interpretation--false-positive-reduction)
- [Remediation Guidance by Vulnerability Class](#remediation-guidance-by-vulnerability-class)
- [Responsible Testing](#responsible-testing)
- [Further Reading](#further-reading)

---

## Testing Approaches: Black-Box vs. Grey-Box

ASTF is fundamentally a **black-box, dynamic** tool — it never reads your source code. Every test case sends real HTTP requests to a running API and draws conclusions from real HTTP responses (status codes, headers, body content, timing). This is deliberate: it means ASTF's findings are things an actual external attacker could observe, not static-analysis guesses about what *might* be reachable.

Within that black-box model, you control how much information ASTF starts with — this is the real "black-box vs. grey-box" choice for this tool:

| Mode | How to invoke it | What you get |
|---|---|---|
| **Pure black-box** | `-u https://api.example.com` with no `--token`, no endpoints file | ASTF probes for an OpenAPI/Swagger spec, tries common REST path patterns, and falls back to a hardcoded list if nothing is found. Fastest to start, weakest coverage — you're only as good as what auto-discovery finds. |
| **Grey-box via known endpoints** | `--endpoints-file endpoints.txt --no-discovery` | You supply the exact `METHOD /path` list (exported from your own OpenAPI spec, a HAR capture, or written by hand). Every test case runs against every endpoint you listed — no guessing, no missed routes. This is the highest-value mode for a real assessment of an API you have some access to. |
| **Grey-box via authenticated identity** | add `--token`, and `--secondary-token` for a second identity | Reveals everything behind auth (which is most of a real API) and unlocks cross-user authorization testing — the single most valuable technique in this framework (see [Authorization Testing Methodologies](#authorization-testing-methodologies)). |
| **Grey-box via known request shapes** | `--endpoints-file` entries plus a config-file endpoint block with a real request body | Injection test cases (`ASTF-INJECTION-2023`, `ASTF-API10-2023`) prefer the endpoint's *actual* body fields over a generic guessed list — giving ASTF a real sample body materially improves both detection accuracy and reduces wasted requests on wrong field names. |

**Recommendation:** never run a security assessment in pure black-box mode alone. At minimum, supply an authenticated token — most of the OWASP API Top 10 categories (BOLA, BFLA, BOPLA, excessive data exposure) are meaningless against unauthenticated endpoints, since there's no access-control boundary to violate in the first place.

---

## Planning an Engagement

A realistic order of operations, not just "run the scanner once":

1. **Get authorization first.** See [Responsible Testing](#responsible-testing) — this is not optional, even against your own staging environment.
2. **Establish two distinct identities if you can.** Register or provision two ordinary user accounts (not admin accounts) that own *different* resources of the same type — two different orders, two different profiles, two different videos. This is what `--secondary-token` needs, and it's the difference between "the check ran" and "the check actually proved something."
3. **Run a broad first pass** with discovery enabled and both tokens set, all test cases active:
   ```bash
   java -jar astf.jar -u https://api.example.com \
     --token "$PRIMARY_TOKEN" --secondary-token "$SECONDARY_TOKEN" \
     -f HTML -o first-pass.html -v
   ```
4. **Narrow and re-test.** Once you see which endpoints and findings matter, isolate them:
   ```bash
   # Re-test just the endpoints that produced findings, with just the relevant test case
   java -jar astf.jar -u https://api.example.com \
     --endpoints-file suspect-endpoints.txt --no-discovery \
     --token "$PRIMARY_TOKEN" --secondary-token "$SECONDARY_TOKEN" \
     --test-cases ASTF-API1-2023,ASTF-API5-2023
   ```
5. **Manually replay anything CRITICAL or HIGH before reporting it.** Every finding includes `requestDetails` — the exact method and URL used. Reproduce it with `curl` yourself. A tool making a claim and a human confirming the claim are different levels of evidence; don't skip the second one for anything you're about to hand to a developer as "you have this vulnerability."
6. **If you have a client certificate, test mTLS separately** with `--client-cert` and `--invalid-client-cert` (see below) — this needs deliberate setup, so it's easy to forget in a rushed assessment.

---

## Authentication Testing Strategies

Maps to `ASTF-API2-2023` (`BrokenAuthenticationTestCase`), plus authentication-adjacent checks inside `ASTF-GRAPHQL-2023` and the dedicated `ASTF-MTLS-2023`.

| Technique | What it proves | How ASTF tests it |
|---|---|---|
| **Missing authentication** | An endpoint that should require a token doesn't | Requests the endpoint with no `Authorization` header at all; flags an unexpected 2xx |
| **JWT "none" algorithm** | The server trusts a token's claims without verifying a signature | Forges a token with `alg: none` and an empty signature segment, submits it, checks for acceptance |
| **JWT `kid` path traversal** | The server resolves the signing key from an attacker-controlled `kid` header value | Sets `kid` to `../../../dev/null` and signs with an empty-string HMAC secret (a `kid` pointing at an empty/predictable file yields a known key) |
| **JWT algorithm confusion (RS256→HS256)** | The server accepts an HMAC-signed token when it expects an RSA-signed one, using the RSA **public** key (which is, well, public) as the HMAC secret | Fetches the real JWKS, extracts the RSA public key, signs a forged token with HS256 using that key's raw bytes as the secret |
| **JWT `jku` header abuse** | The server fetches the signing key from an attacker-specified URL in the `jku` header instead of a pinned, trusted key set | Sets `jku` to an ASTF-controlled probe URL and looks for a fetch attempt (timing-based; full exploitation needs an attacker-hosted key, which is out of scope for automated detection) |
| **Username/password enumeration** | Login responses differ between "no such user" and "wrong password," letting an attacker build a valid-username list | Compares the response for a random username against a common one (`admin`) |
| **Brute-force / credential stuffing resistance** | The login endpoint has no lockout or rate-limit after repeated failures | Sends 8 consecutive failed logins; flags if none produce HTTP 429/423 |
| **GraphQL argument-based auth bypass** | A `me`/`viewer`/`currentUser` query field trusts a `token` **argument** instead of (or in addition to) the `Authorization` header, without validating its signature | Calls `{me(token: "<none-alg JWT>"){...}}` directly as a query argument |
| **Mutual TLS (mTLS) validation** | The server accepts *any* client certificate rather than verifying the trust chain | Presents a valid cert (`--client-cert`) and separately a deliberately invalid/self-signed one (`--invalid-client-cert`); if both are accepted, the server isn't actually validating certificates |

**Strategy notes:**
- Run the JWT checks against a token-issuing endpoint you control, or your own test account's token — never against a token you don't have explicit permission to attack, even if it's technically reachable.
- The `kid`/`jku`/algorithm-confusion checks need a real JWKS endpoint to be meaningful; if the target has none, expect (and don't worry about) a true negative.
- mTLS testing (`--client-cert`, `--invalid-client-cert`) is the one authentication check that needs manual setup — you need actual PKCS12 keystores. It's the check most likely to be skipped by accident; don't forget it if the target uses client certs at all.

---

## Authorization Testing Methodologies

This is where ASTF's black-box model earns its keep, because authorization bugs are invisible from a single identity's point of view — you need at least two.

### BOLA/IDOR (`ASTF-API1-2023`)

Three distinct techniques, in increasing order of how convincing the evidence is:

1. **Numeric/UUID substitution** (single identity) — swap the ID in the path (`/orders/42` → `/orders/1`, `/orders/43`...) and check whether a different-looking resource comes back successfully. Weakest signal: proves the *pattern* is exploitable but not that a specific unauthorized access happened.
2. **Cross-user access** (needs `--secondary-token`) — request the *exact same URL*, no ID substitution, once with each identity's token. If both succeed, that's direct proof neither identity's ownership was checked — not an inference. **This is the strongest BOLA evidence ASTF produces**, and it's exactly why setting up two real accounts (see [Planning an Engagement](#planning-an-engagement)) is worth the extra few minutes.
3. **Templated-path resolution** — when the path is a literal OpenAPI placeholder (e.g. `/books/{book_title}`), ASTF resolves it to a real value discovered from the corresponding collection endpoint first, so the ID-manipulation and cross-user checks above have something real to work against instead of a dead template string.

### BFLA (`ASTF-API5-2023`)

Two complementary techniques:

1. **Root-relative admin path probing** — tries generic admin-shaped paths (`/admin`, `/internal`, `/manage`, `/console`, ...) appended to the base URL, and separately tries escalating the HTTP method (GET succeeds → does PUT/DELETE/PATCH also succeed?) on the same endpoint.
2. **Privilege-tier path substitution** — takes an already-known, specific endpoint whose path contains a low-privilege segment (`user`, `customer`, `member`, `public`) and swaps just that segment for a high-privilege one (`admin`, `staff`, `internal`, `management`, `superuser`), replaying the identical request with the identical (non-elevated) token. This exists specifically because the most common real-world BFLA pattern is a "sibling" endpoint that looks harmless by naming convention alone — `DELETE /api/v2/user/videos/{id}` denying you while `DELETE /api/v2/admin/videos/{id}` silently succeeds with the same token is a real, live-confirmed pattern this technique catches.

### BOPLA / Mass Assignment / Excessive Data Exposure (`ASTF-API3-2023`)

- **Excessive data exposure**: scans GET responses for sensitive field names (`password`, `secret`, `ssn`, `credit_card`, ...) that shouldn't be in a client-facing payload.
- **Mass assignment**: sends a POST/PUT with extra, unexpected privileged fields (`isAdmin`, `role`, `credit`, ...) injected into the body and checks whether the server accepted and applied them.

**Strategy note:** Authorization testing is the category where "the check ran and found nothing" is least trustworthy on its own — a missing finding could mean the target is genuinely secure, or it could mean ASTF never discovered the right endpoint/identity/path shape to test. Cross-check anything security-critical manually, especially endpoints your discovery pass might have missed (see [Result Interpretation](#result-interpretation--false-positive-reduction)).

---

## Data Validation Testing Techniques

Injection and input-validation coverage spans three test cases:

| Test case | Surface | Payload classes |
|---|---|---|
| `ASTF-INJECTION-2023` (`SqlNoSqlInjectionTestCase`) | Ordinary REST body fields *and* path parameters (resolved or unresolved template segments), independent of HTTP method | Bare `'`, tautology (`' OR '1'='1`), UNION-based SQL payloads; MongoDB operator payloads (`{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`) for NoSQL auth-bypass and query-manipulation |
| `ASTF-API10-2023` (`UnsafeConsumptionOfApisTestCase`) | Webhook/integration/proxy/sync-named endpoints specifically — third-party API consumption is a distinct trust boundary from your own API's direct input | Script injection, path traversal, SQL fragments; also checks for open redirect via `redirect`/`callback` parameters |
| `ASTF-GRAPHQL-2023` resolver injection | Every discovered GraphQL mutation *and* query field with a string argument (not just the first few — every candidate field is tested) | The same SQL/OS-command/XSS/path-traversal battery, plus SSRF-shaped payloads specifically for arguments named like `url`/`host`/`endpoint` |
| `ASTF-REDOS-2023` (`RegexDosTestCase`) | Any body field | Pathological repeated-character strings designed to trigger catastrophic backtracking in a vulnerable regex; detected via response-time comparison against a baseline |

**Detection is evidence-based, not payload-echo-based:** SQL injection is only flagged when a real database error signature appears in the response (SQLite, PostgreSQL, MySQL, SQLAlchemy, Hibernate, Sequelize, and half a dozen other stack-specific error patterns are matched) — a payload merely being accepted doesn't produce a finding. This matters for your own false-positive triage: if you see a SQL injection finding, the response body genuinely contained a database error string, which you can go read yourself in `evidence`.

**Strategy note on ReDoS specifically:** a ReDoS finding means ASTF sent one request that didn't return within a generous multiple of the endpoint's normal response time. Before treating this as confirmed, re-run the exact same request a second time manually — transient network/server slowness produces the same signal as a real catastrophic-backtracking bug, and this is the one data-validation check where a single sample is genuinely less reliable than the others.

---

## Rate Limiting Test Approaches

Rate limiting is tested in two places, both using the same core technique — burst requests, then check for a rejection signal:

- `ASTF-API4-2023` (`UnrestrictedResourceConsumptionTestCase`) — general resource-consumption endpoints.
- `ASTF-API6-2023` (`UnrestrictedAccessToSensitiveFlowsTestCase`) — specifically login, OTP, payment, and password-reset flows, where missing rate limiting has outsized impact (credential stuffing, OTP brute-forcing).
- The GraphQL login-mutation brute-force check (part of `ASTF-GRAPHQL-2023`) applies the same idea to a GraphQL-shaped login call, since a REST-oriented rate-limit test never sends a `{"query": "..."}` body and would never reach a GraphQL login mutation at all.

**What counts as "missing":** the endpoint returns HTTP 429 (Too Many Requests) or a 423 (Locked), or a body-level message like "rate limit exceeded"/"too many requests"/"throttled" — the check also handles APIs that signal rejection via a 200 status with an explicit failure message in the body, rather than assuming every rate limiter uses the "correct" HTTP status. If none of these ever appear across the burst, ASTF flags missing rate limiting.

**This is the one category where running the scanner generates real load on purpose.** Before testing rate limiting against anything shared or production-adjacent:
- Confirm you have explicit authorization for the volume of requests this generates (each rate-limit check alone can be 8–20 requests to the same endpoint in quick succession, times however many qualifying endpoints exist).
- Consider `--threads 1` and a narrowed `--test-cases`/`--endpoints-file` scope if you're testing against infrastructure you don't fully control, to avoid an accidental self-inflicted denial-of-service.
- A missing-rate-limit finding on a **public, unauthenticated** endpoint is usually a lower priority than the identical finding on a login or payment endpoint — read the endpoint, not just the title, before triaging severity.

---

## GraphQL-Specific Methodology

`ASTF-GRAPHQL-2023` covers substantially more than REST-equivalent checks translated to GraphQL syntax:

- **Schema exposure**: introspection enabled in production, and field-suggestion leakage ("Did you mean...?" hints that enable schema enumeration even with introspection disabled).
- **Denial of service**: query-depth attacks (deeply nested queries), batch-query abuse (arrays of operations bypassing per-request rate limits), field-duplication, alias-based, and circular-fragment attacks — all four DoS variants use response-timing comparison against a baseline, the same reliability caveat as ReDoS applies here.
- **Resolver-level injection**: every mutation and query field with a string argument (not bounded to the first few discovered — every candidate is tested, since a real API's vulnerable field is just as likely to be the 15th discovered field as the 1st).
- **IDE/tooling exposure**: GraphiQL or similar interactive consoles reachable in production, including a cookie-based bypass variant for consoles gated behind a client-controllable "debug" flag.
- **Deny-list bypass via fragment wrapping**: a sensitive field blocked by name when called directly, but reachable when referenced only through a GraphQL fragment — a strong signal the block is a naive string filter on the raw query text rather than real AST-based access control.
- **Argument-based auth bypass and login brute-force** — see [Authentication](#authentication-testing-strategies) and [Rate Limiting](#rate-limiting-test-approaches) above.

**Strategy note:** GraphQL testing needs introspection to be reachable to enumerate mutations/queries in the first place. If introspection is genuinely disabled *and* field-suggestion leakage is also absent, most of the injection/DoS-field-targeting checks have nothing to enumerate against — this shows up as an honest "no finding," not a tool failure. Consider supplying known field names via `--endpoints-file` request-body content if you have the schema from another source (documentation, a `.graphql` schema file) even when introspection is locked down.

---

## gRPC-Specific Methodology

`ASTF-GRPC-2023` is detection-and-enumeration focused, not a full gRPC fuzzing tool:

- Detects gRPC services by content-type (`application/grpc`) and probes standard service paths, including the health-check service.
- Separately checks whether server reflection (`grpc.reflection.v1alpha.ServerReflection`) is active — this is gRPC's equivalent of GraphQL introspection, and its exposure means an attacker can enumerate every service and method without a `.proto` file.
- gRPC injection testing exists at a scoped, detection level; full request/response fuzzing against a specific service requires the service's actual `.proto` schema, which is outside what a black-box HTTP-based tool can derive on its own.

**Strategy note:** if `h2c` (HTTP/2 cleartext, no TLS) is in use, make sure your test client/proxy setup actually supports it — plain HTTP/1.1 tooling will silently fail to even reach a gRPC service running over h2c, which looks identical to "no gRPC service present" if you're not specifically checking for it.

---

## Result Interpretation & False-Positive Reduction

### Reading a `Finding`

| Field | What it tells you | How to use it |
|---|---|---|
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO | Triage order — but re-read the endpoint before trusting the label blindly (see rate-limiting note above) |
| `evidence` | The specific signal that triggered the finding — an error string, a status-code pair, a response-time delta | This is your first, fastest manual-verification step: does the evidence actually look like what it claims to be? |
| `requestDetails` / `responseDetails` | The literal request(s) sent and response(s) received | Copy-paste these into `curl` to reproduce independently before reporting anything CRITICAL/HIGH |
| `testCaseId` | Which check produced this, and its OWASP mapping | Useful for filtering (`--test-cases`/`--exclude-tests`) on a re-run |
| `remediation` | Framework-agnostic-to-specific fix guidance | Hand directly to the developer who owns the endpoint |

### Built-in false-positive guards (already handled for you)

ASTF's test cases already filter out several common false-positive classes — worth knowing so you don't second-guess a correct result:

- **SPA/reverse-proxy HTML fallback**: a single-page app or catch-all reverse proxy that returns HTTP 200 + `text/html` for every unknown path would otherwise look like every "shadow endpoint" or "admin path" guess succeeded. Checks that would be fooled by this compare Content-Type and body shape (JSON/XML expected) before flagging.
- **"Success" that's actually a body-level failure message**: some APIs return HTTP 200 on both successful and failed operations, signaling failure only in the JSON body (`"status":"fail"`, `"success":false`, "invalid credentials", ...). Auth-bypass and injection checks that rely on "did this succeed" check for these markers before counting a 2xx as real success.
- **Documentation endpoints that are legitimately HTML**: `/docs`, `/redoc`, `/swagger-ui.html` are supposed to return HTML — the exposed-documentation check fetches a deliberately nonexistent path first as a baseline, so it can tell "this is real Swagger UI" apart from "this is just the same fallback page every path returns."

### What you should still verify yourself

- **Anything CRITICAL or HIGH**, before it goes in a report to a development team — see [Planning an Engagement](#planning-an-engagement), step 5.
- **A "no finding" on a check that matters to your assessment.** Absence of a finding can mean "genuinely not vulnerable" or "ASTF never got a real value to test against" (unresolved endpoint, missing auth, field name it didn't guess). If a category is business-critical, don't take silence as clearance without at least one manual spot-check.
- **Timing-based findings** (ReDoS, GraphQL DoS variants) — re-run once manually; a slow network hop produces the identical signal as a real vulnerability.

---

## Remediation Guidance by Vulnerability Class

Each `Finding.remediation` field already contains specific guidance for the exact finding — this table is for triage-level planning across a whole report:

| OWASP category | Typical fix |
|---|---|
| API1 — BOLA | Enforce object-level ownership checks in the data-access layer, not just authentication. Don't rely on ID unpredictability (UUIDs) as the only control. |
| API2 — Broken Authentication | Reject `alg: none`; validate JWT signatures against an explicit algorithm allowlist; never resolve signing keys from client-controlled `kid`/`jku` values without strict validation; implement account lockout/rate limiting on login. |
| API3 — BOPLA | Use explicit response DTOs/serializers rather than returning ORM entities directly; validate and allowlist which fields a client can set on write operations. |
| API4 — Unrestricted Resource Consumption | Rate-limit at the gateway or application layer; return 429 with `Retry-After`; cap pagination/page-size parameters. |
| API5 — BFLA | Enforce role checks in the resolver/controller layer for *every* endpoint independently — never let a path's naming convention (`/admin/...`) be the only thing distinguishing its authorization requirements from a sibling path. |
| API6 — Unrestricted Access to Sensitive Flows | Apply stricter rate limiting and (where appropriate) CAPTCHA/bot detection specifically on login, OTP, password-reset, and payment flows. |
| API7 — SSRF | Validate and allowlist destination hosts before any server-side outbound request; block link-local/metadata IP ranges (`169.254.169.254`, etc.) at the network layer as defense in depth. |
| API8 — Security Misconfiguration | Add standard security headers; return generic error messages to clients, log full detail server-side only; disable framework debug/development modes in production. |
| API9 — Improper Inventory Management | Maintain an accurate, current API inventory; properly decommission deprecated versions and non-production environments rather than leaving them publicly reachable. |
| API10 — Unsafe Consumption of APIs | Treat third-party/webhook input with the same validation rigor as direct user input; validate redirect targets against an allowlist. |
| GraphQL | Disable introspection in production; enforce query depth/complexity limits; validate resolver arguments before use in any downstream query/command; use AST-based (not string-matching) access control. |
| gRPC | Disable server reflection in production unless deliberately exposed for internal tooling; enforce TLS (or mTLS) rather than plaintext/h2c where the deployment allows it. |
| Injection (SQL/NoSQL/ReDoS) | Use parameterized queries/ORMs everywhere; validate input types strictly (reject an object where a string/number is expected — this is what stops NoSQL operator injection); avoid user-controlled input in regex patterns, or use a regex engine/library with backtracking limits. |
| mTLS | Actually validate the client certificate's trust chain — don't accept any presented certificate as proof of identity. |

---

## Responsible Testing

- **Get explicit written authorization** before scanning any target you don't own outright, including your employer's staging environment if it's shared infrastructure — the same courtesy applies whether the target is a public bug-bounty scope, a client engagement, or an internal system with other stakeholders.
- **Never point ASTF at a target you don't have permission to test**, including the public demo instances referenced in this project's own documentation (VAmPI, crAPI, DVGA, gRPC Goat) — those are intentionally vulnerable and meant for exactly this kind of testing, which is why they're safe defaults for learning the tool, but the same courtesy doesn't extend to arbitrary production APIs.
- **Use dedicated test accounts, not real user data**, for the two-identity cross-user authorization techniques above — an account takeover proof-of-concept (e.g. an actual password change, as ASTF's BOLA check can produce) should only ever happen against accounts you created for this purpose.
- **Rate-limiting and DoS-shaped checks generate real load** — see the dedicated warning in [Rate Limiting Test Approaches](#rate-limiting-test-approaches).
- **Injection payloads can have real side effects** against a genuinely vulnerable target — SQL/NoSQL injection payloads that succeed are, definitionally, executing against a real database; OS-command-injection-shaped payloads sent to a resolver that's actually vulnerable can execute real shell commands. Treat a CRITICAL injection finding as proof the underlying system needs to be treated carefully going forward, not just as a line in a report.

---

## Further Reading

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) — the vulnerability catalog this framework is built around
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — broader methodology this guide deliberately doesn't duplicate
- [Framework Overview](FRAMEWORK_OVERVIEW.md) — what ASTF does and how it's architected
- [Architecture](ARCHITECTURE.md) — component design and how to add a new test case
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and how to fix them
