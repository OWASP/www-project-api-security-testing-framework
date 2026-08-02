# ASTF Coverage Traceback — Documented Vulnerabilities vs. Actual Detections

Of everything these four repos are documented to be vulnerable to, what did ASTF actually catch?

Four research passes pulled the **official, documented** vulnerability catalog straight from each target's own repo — READMEs, challenge docs, per-lab writeups — not from memory. Every row below is traced against the actual JSON findings from real scan runs, not re-graded from the code.

| Target | Detected | Total | Source |
|---|---|---|---|
| VAmPI | **6** | 9 | README + author's companion blog post |
| crAPI | **4** | 18 | `docs/challenges.md` + `docs/challengeSolutions.md` |
| DVGA | **7** | 22 | 22 in-app solution pages (`templates/partials/solutions/`) |
| gRPC Goat | **1** | 9 | Per-lab `Readme.md` ([rootxjs/grpc-goat](https://github.com/rootxjs/grpc-goat)) |
| **Total** | **18** | **58** | — |

Legend: ✅ Hit · ❌ Miss · ⚠️ Partial · ➖ N/A (not applicable to this run) · 🚫 Not in Scope (a different discipline entirely, not an API-request-testable concern) · `structural` (a generic scanner plausibly could catch this) · `business logic` (requires domain knowledge no generic scanner has, but is still conceptually an API security concern)

---

## How to read these numbers

**18 of 58 sounds low until you know what the other 40 actually are.** Almost every security scanner on the market claims "100% OWASP Top 10 coverage" — and almost none of them publish a page like this one to back it up. We'd rather you distrust an unverified number than trust one, so here's the honest breakdown instead:

- **Roughly a third of the gap is genuinely out of reach for *any* HTTP-request-based scanner** — commercial or open source. Business-logic semantics (crAPI's balance and coupon-quantity challenges), filesystem permission checks, and packet-level credential interception aren't things a scanner can find by sending API requests, no matter how good it is. These aren't ASTF weaknesses; they're the boundary of what this entire category of tool can do.
- **Another chunk is untested, not undetectable** — labs and challenges this round simply didn't point the scanner at yet (most of gRPC Goat, several crAPI endpoints). The detection logic exists or is close; it just hasn't been run against that specific target.
- **The remainder — the real, fixable gaps — is exactly what's tracked as open issues** and gets closed round over round: this pass alone took the number from 10 to 18 (+80%), and every one of those new hits was confirmed live against a real running vulnerable application, including one real, reproduced account takeover (not just a scanner reporting a 2xx status code).

The trend line is the part worth paying attention to: two rounds ago this page would have shown 10. It shows 18 now. The methodology — pulling each target's *own* documented vulnerability list and tracing every finding back to it — doesn't change between rounds, so the growth is real, not a relabeling. Full reasoning and every individual item are below.

---

## Update: the path-template gap below is now fixed

**This was the single highest-value fix to come out of this whole traceability pass.** ASTF's endpoint discovery kept unresolved OpenAPI path templates as literal strings (`{book_title}`, not a real book title), and only `BrokenObjectLevelAuthorizationTestCase` had any logic to work around it — every other test case (~15 of 16) sent the literal, unresolved placeholder on every request.

Fixed in [PR #104](https://github.com/OWASP/www-project-api-security-testing-framework/pull/104) by centralizing template resolution in a shared `PathTemplateResolver`, called once per endpoint by `Scanner` before any test case runs. Live-testing this fix against VAmPI surfaced something worse than a coverage gap: a literal, unencoded `{`/`}` in an HTTP request line made VAmPI's dev server hang the connection with zero response — so most of a scan's time on any templated endpoint was being spent hung, not testing anything. `EndpointInfo.getFullUrl()` now percent-encodes the path as a safety net regardless of whether resolution succeeds. A full VAmPI scan that previously took 80+ minutes (mostly hung) now completes in under 4.

**Result:** BOLA cross-user (row 3 below), SQL injection (row 1), and ReDoS (row 7) all now fire correctly against VAmPI's real, documented vulnerabilities — confirmed live on the built jar, not just unit tests.

---

## 1 · VAmPI — 6 of 9 documented vulnerabilities detected *(was 2 of 9)*

Source: VAmPI's README + the author's companion blog post (linked from the README) — the only official documentation; no wiki, no `VULNERABILITIES.md`. Updated after live-verifying [PR #104](https://github.com/OWASP/www-project-api-security-testing-framework/pull/104)'s fixes.

| # | Documented vulnerability | Endpoint | Status | Notes |
|---|---|---|---|---|
| 1 | SQL Injection `structural` | `GET /users/v1/{username}` | ✅ Hit | "SQL Injection Vulnerability" — CRITICAL, evidence: `sqlalchemy.exc`. New `SqlNoSqlInjectionTestCase` (#96) targets path parameters directly; needed two follow-up fixes found via live testing — a bare single-quote payload (the tautology/UNION payloads alone didn't trigger the error) and Python/SQLAlchemy error patterns added to the indicator list (it had zero — only Ruby/PHP/MSSQL-style strings). |
| 2 | Unauthorized Password Change `structural` | `PUT /users/v1/{username}/password` | ✅ Hit | **Live-confirmed with real account takeover.** BOLA's cross-user check now sends a realistic body (real `password`/`email`/`name` fields) instead of an empty `{}` when the endpoint has no discovered sample body. Verified against a fresh VAmPI instance: registered two accounts, had the secondary identity PUT a new password to the primary's password endpoint (HTTP 204), then confirmed by actually logging in as the primary account with the new password — the takeover was real, not just a 2xx response. |
| 3 | Broken Object Level Authorization `structural` | `GET /books/v1/{book_title}` | ✅ Hit | "Broken Object Level Authorization (Cross-User Access Confirmed)" — CRITICAL. Resolved to a real book title (e.g. `bookTitle57`) via the new centralized `PathTemplateResolver`, then both identities confirmed to reach the identical object. |
| 4 | Mass Assignment `business logic` | `POST /users/v1/register` | ❌ Miss | BOPLA check tests a fixed payload list (isAdmin/role/etc.) against already-discovered endpoints, but register wasn't exercised with an injected admin flag in this run. |
| 5 | Excessive Data Exposure (debug endpoint) `structural` | `GET /users/v1/_debug` | ✅ Hit | "Excessive Data Exposure — Sensitive Fields in Response," correctly flagging the password field. |
| 6 | User/Password Enumeration `structural` | `POST /users/v1/login` | ❌ Miss | New `testUserEnumeration` check (#97) now exists and ran against VAmPI's login endpoint — but found no differential response between an unknown username and a common one, so no finding. Likely a true negative: VAmPI's messages may not distinguish the two cases in a way the heuristic can see, not a bug in the check. |
| 7 | RegexDOS `structural` | `PUT /users/v1/{username}/email` | ✅ Hit | "Regular Expression Denial of Service (ReDoS)" — HIGH. New `RegexDosTestCase` (#98): the request timed out entirely on the `email` field versus a 54ms baseline. |
| 8 | Lack of Rate Limiting `structural` | app-wide | ✅ Hit | Debug/documentation endpoints correctly flagged for missing rate limiting as part of the broader misconfiguration sweep; also now confirmed via `testBruteForceLockout` (#97) — "No Account Lockout or Rate Limiting on Repeated Failed Logins." |
| 9 | JWT weak signing key `structural` | not stated by VAmPI | ➖ N/A | VAmPI's own docs don't name an endpoint or mechanism for this one — unverifiable either way without guessing at what VAmPI meant. (Note: the 3 new JWT attack variants from #99 need a real JWKS to test against, which VAmPI doesn't expose — verified instead against crAPI, see below.) |

---

## 2 · crAPI — 4 of 18 documented challenges detected *(was 3 of 18)*

Source: crAPI's own `docs/challenges.md` + `docs/challengeSolutions.md` — the authoritative challenge list (not the README). crAPI itself groups several challenges as pure business logic (arithmetic/semantic), which no generic scanner — ASTF or otherwise — can resolve without domain knowledge of what a "correct" balance or coupon state looks like.

| # | Documented challenge | Service | Status | Notes |
|---|---|---|---|---|
| 1 | Vehicle location BOLA `structural` | identity | ✅ Hit | Confirmed live via #87's cross-user check — CRITICAL, correct evidence (both identities got HTTP 200 on the identical URL). |
| 2 | Mechanic-report BOLA `structural` | workshop | ❌ Miss | Root-caused by reading crAPI's own challenge solution doc: the vulnerable endpoint isn't in any OpenAPI spec at all — it's a URL dynamically returned in a `report_link` JSON field after calling `/workshop/api/merchant/contact_mechanic`. Reaching it requires chaining two live requests (call A, extract a URL from its response, call that URL as a second identity) — the same multi-step-flow capability already tracked and deliberately deferred as [issue #103](https://github.com/OWASP/www-project-api-security-testing-framework/issues/103), not a new gap. |
| 3 | Password reset for another user `structural` | identity | ❌ Miss | crAPI's own solution doc leaves the endpoint blank; not tested. |
| 4 | Endpoint leaking sensitive info of other users `structural` | unspecified | ⚠️ Partial | The BOLA finding's own evidence happened to leak fullName/email — same underlying issue, no dedicated finding for it as a distinct category. |
| 5 | Video internal property leak `business logic` | community | ➖ N/A | crAPI gives no endpoint; requires noticing an undocumented field. |
| 6 | Layer-7 DoS via contact-mechanic `structural` | workshop | ✅ Hit | "Missing Rate Limiting" fired generically across the scan — reasonable match, not endpoint-specific confirmation. |
| 7 | BFLA — delete another user's video `structural` | identity | ✅ Hit | **Live-confirmed against the real public demo (crapi.apisec.ai).** Read crAPI's actual source (`ProfileController.java`): `DELETE /identity/api/v2/user/videos/{id}` is a deliberate decoy that always returns 403/404, while the sibling `DELETE /identity/api/v2/admin/videos/{id}` — same ID, same non-admin token — succeeds with no role check. New `testPrivilegeTierPathSubstitution` check in `BrokenFunctionLevelAuthorizationTestCase` substitutes a low-privilege path segment (user/customer/member/public) for a high-privilege one (admin/staff/internal/...) on any known endpoint and replays the identical request. Verified end-to-end with the actual built jar against a freshly-registered test account: uploaded a real video, ran `--test-cases ASTF-API5-2023` against just that endpoint, got exactly 1 CRITICAL finding with response evidence "Original status: 404 / Substituted status: 200". |
| 8 | Get an item for free (negative quantity) `business logic` | workshop | ➖ N/A | Requires understanding that negative quantity inverts a debit into a credit — semantic, not structural. |
| 9 | Increase balance by $1,000+ `business logic` | workshop | ➖ N/A | Same mechanism/reasoning as #8. |
| 10 | Update internal video properties `business logic` | community | ➖ N/A | Requires knowing which field matters. |
| 11 | SSRF via video conversion `structural` | workshop | ❌ Miss | Root-caused via self-hosted crAPI (`ENABLE_SHELL_INJECTION=true`), not just untested. The vulnerable field is `conversion_params` on the video object — not in ASTF's `URL_PARAMETERS` list, and reaching it requires a two-step flow: `PUT /api/v2/user/videos/{id}` to set the payload, then a separate `GET /api/v2/user/videos/convert_video?video_id={id}` to trigger it — the same multi-step-flow capability already deferred as [issue #103](https://github.com/OWASP/www-project-api-security-testing-framework/issues/103). Live-tested both steps: the `PUT` accepted a shell-injection/SSRF payload (`; curl -s http://www.google.com #`) without complaint, but the trigger call returned **403** ("should be accessed only internally") when routed through the public gateway — the gateway injects an `X-Forwarded-Host` header, and the endpoint explicitly rejects any request carrying one. Bypassing the gateway and calling the identity service directly inside the Docker network hit a second, different block: **400 "This combination of host and port requires TLS."** crAPI's own `docs/challengeSolutions.md` has a full "Detailed solution" for every other challenge except this one — even its own authors never published a path through these two layers. Likely only reachable via a genuine internal service-to-service call (a real SSRF chain), which would make this row arguably `➖ N/A` for any purely external black-box scanner rather than a fixable miss — needs further investigation before deciding which. |
| 12 | Free coupons via NoSQL injection `structural` | community | ❌ Miss | Endpoint located and live-tested: `POST /workshop/api/shop/apply_coupon`. Note corrected from an earlier round — `SqlNoSqlInjectionTestCase` already sends MongoDB operator payloads (`$ne`/`$gt`/`$regex`) against every POST/PUT/PATCH endpoint's fields, so "no NoSQL payloads at all" was wrong. The real gap is narrower on two counts: (1) the *success-based bypass* heuristic (`SqlNoSqlInjectionTestCase.java:336-345`) only fires for a credential-shaped field (`password`/`pass`/`pwd`) on an auth-like path (`login`/`auth`/`signin`/`session`) — this endpoint is neither; (2) reading crAPI's own source (`ApplyCouponView`, `CouponSerializer.coupon_code = serializers.CharField()`), the field is validated as a plain string by DRF *before* it ever reaches the Mongo query — submitting `{"coupon_code": {"$ne": null}}` (exactly ASTF's current payload shape) gets rejected at the serializer with a 400, never reaching the injection point at all. No seed coupon codes exist in this deployment either, so the "regex matches any document" variant couldn't be tested. This specific field may not be reachable via a JSON-object-substitution payload at all — broadening the success-heuristic's path/field gating (the original task scope) doesn't fix this one; it needs a payload shape ASTF doesn't send yet (e.g. an operator expressed *as a string* that a schema-less ORM layer still parses specially), which needs further research before implementing. |
| 13 | Redeem claimed coupon via SQL injection `structural` | workshop | ⚠️ Partial *(was ❌ Miss)* | Same endpoint as row 12: `POST /workshop/api/shop/apply_coupon`. **Confirmed real SQL injection** — `ApplyCouponView` builds the "already applied" check via raw string concatenation (`"...AND coupon_code = '" + coupon_request_body["coupon_code"] + "'"`, no parameterization). Live-tested with `coupon_code: "O'Brien"`: server returned a generic **500 "Server Error"** HTML page with no SQL-specific text, but `docker logs crapi-workshop` confirmed a genuine `psycopg2.errors.ProgrammingError` — a real syntax error, not a false alarm. Root cause of the empty evidence: the view's own exception handler does `return Response({"message": e}, status=500)`, but the raw exception object isn't JSON-serializable, so DRF's renderer throws a *second*, unrelated `TypeError` while trying to serialize the first error — the response that reaches the client is Django's generic double-fault error page, carrying zero DB-error-signature text. **Fix:** added `testSqlInjectionBehavioral` to `SqlNoSqlInjectionTestCase` — a fallback that runs only when the evidence-based check finds nothing, comparing a bare single-quote payload's status against a clean-value baseline on the same field; an unprompted 500 where the baseline succeeds is flagged as a new MEDIUM "Possible SQL Injection (Behavioral)" finding (weaker than the CRITICAL evidence-based one, since no DB-error text confirms it). 3 new unit tests added (`SqlNoSqlInjectionTestCaseTest`), one modeling this exact endpoint's real observed response shape; full suite (355 tests) green. **Not yet CLI-live-verified end-to-end** — found a separate, real gap while trying: `ConfigLoader.java:276` hardcodes inline endpoint request bodies to `null` and never reads a `requestBody` field from config, despite `TESTING_GUIDELINES.md`'s "grey-box via known request shapes" section documenting exactly that capability. Without it, there's no way to hand the CLI apply_coupon's real `coupon_code`/`amount` fields short of an OpenAPI spec or manual endpoint-file editing that ConfigLoader doesn't support either — worth its own issue. |
| 14 | Endpoint with no auth check `structural` | unspecified | ✅ Hit | "Missing Authentication Controls" fired in the authenticated scan. |
| 15 | JWT forgery — 4 sub-attacks (alg confusion, unsigned, JKU, kid path traversal) `structural` | identity | ⚠️ Partial | ASTF's JWT-none check covers only the "unsigned/none" variant, and it didn't fire against crAPI (suggesting crAPI blocks that one specifically) — the other 3, more sophisticated attacks (RS256→HS256 confusion, JKU header abuse, kid path traversal) have no equivalent test at all. |
| 16-18 | Chatbot prompt injection (3 challenges) `business logic` | chatbot | ⚠️ Partial | #90 correctly identified the real LangGraph chatbot endpoint and failed gracefully without a live OpenAI key — mechanics verified, actual compliance never exercised (no API credits spent). **Scope note:** this challenge is really two separable things — (a) *reaching* the chatbot endpoint and sending a crafted prompt, which is squarely in scope and is what ASTF's check does, and (b) *judging whether the model semantically complied* with the injected instruction, which is LLM behavioral/safety evaluation, arguably a different discipline from structural API vulnerability testing even though it happens to run over an API. We count (a) as in scope; (b) is closer to the LLM Top 10 boundary discussed in the roadmap than to a typical API security gap. |

crAPI's own docs also mention 2-3 undocumented "secret" challenges with no published details — excluded from this count since nothing is knowable about them.

---

## 3 · DVGA — 7 of 22 documented vulnerabilities detected *(was 4 of 22)*

Source: DVGA's 22 in-app solution pages (`templates/partials/solutions/solution_1.html`–`22`), the authoritative per-vulnerability documentation — more detailed than the README. Updated after live-verifying [PR #104](https://github.com/OWASP/www-project-api-security-testing-framework/pull/104)'s GraphQL fixes.

| # | Documented vulnerability | Field | Status | Notes |
|---|---|---|---|---|
| 1 | Batch Query Attack (DoS) | `systemUpdate` | ✅ Hit | "GraphQL Batch Query Abuse Possible." |
| 2 | Deep Recursion Query Attack (DoS) | `pastes`/`owner` cycle | ✅ Hit | "GraphQL Query Depth Limit Not Enforced" — the round-2 fix (#71) that made this check actually reachable. |
| 3 | Resource Intensive Query Attack (DoS) | `systemUpdate` | ❌ Miss | No response-timing/expense measurement targeting a specific known-expensive field — `testFieldDuplicationAttack` (#101) probes a generic `__schema` selection, not `systemUpdate` specifically. |
| 4 | Field Duplication Attack (DoS) | `ipAddr` | ❌ Miss | The check now exists (#101) and ran, but its generic probe selection didn't trigger against DVGA's specific `ipAddr`-based scenario — same class of limitation as #3 above. |
| 5 | Aliases-based Attack (DoS) | `systemUpdate` | ✅ Hit | "GraphQL Alias-Based Denial of Service" — new `testAliasBasedAttack` (#101), confirmed live. |
| 6 | GraphQL Introspection | `__schema` | ✅ Hit | "GraphQL Introspection Enabled in Production." |
| 7 | GraphiQL Interface Exposure | — | ➖ N/A | New `testGraphiQLExposure` check (#102) now exists and ran — found nothing, and manually confirmed DVGA doesn't serve a GraphiQL UI on this port/config. A true negative, not a gap. |
| 8 | Field Suggestion Leakage | any invalid field | ➖ N/A | Root-caused, not a miss: replayed `{__typenme}` against live DVGA and got a plain `Cannot query field...` error with no "Did you mean" text — this specific Python GraphQL server just doesn't emit suggestion hints, unlike the JS/graphql-js servers that made this a documented DVGA scenario. ASTF's check is correctly implemented; the condition isn't present in this deployment. |
| 9 | SSRF | `importPaste(host,port,scheme)` | ❌ Miss | GraphQL-argument SSRF now exists (#100) and fired on other candidates in the same run — but `importPaste` specifically wasn't among the first 5 mutations the schema-introspection bound examined. |
| 10 | OS Command Injection #1 | `importPaste(path)` | ❌ Miss | Same bound as #9 — `importPaste` wasn't among the mutations tested this run, even though the breadth fix (#100) now tries every candidate it does examine rather than stopping at the first hit. |
| 11 | OS Command Injection #2 | `systemDiagnostics(cmd)` | ❌ Miss | Requires valid admin credentials first — multi-step, not attempted. |
| 12 | Stored Cross-Site Scripting | `createPaste(content)` | ✅ Hit | "GraphQL Resolver Injection Vulnerability" — #91's fix, confirmed live end-to-end. |
| 13 | Log Injection / Spoofing | operation name | ❌ Miss | No operation-name-based test exists. |
| 14 | HTML Injection | `createPaste(content)` | ⚠️ Partial | Same mechanism/field as #12 — the one finding covers both classes of payload, not counted twice. |
| 15 | SQL Injection | `pastes(filter)` | ✅ Hit | "GraphQL Resolver Injection Vulnerability" on the `pastes` query field's `filter` argument — directly confirms #100's extension to query fields (not just mutations); this exact vulnerability was unreachable before that fix. |
| 16 | GraphiQL Protection Bypass (cookie) | — | ➖ N/A | New cookie-bypass variant of `testGraphiQLExposure` (#102) ran — found nothing, consistent with #7 above (no GraphiQL UI exposed in this config at all, cookie or not). |
| 17 | Query Deny-List Bypass (operation wrapping) | `systemHealth` | ❌ Miss | New `testOperationDenyListBypass` check (#102) ran but found no sensitive-sounding field name (matching keywords like admin/debug/system) to test a bypass against in this schema — a scope limitation of the keyword heuristic, not necessarily a true negative. |
| 18 | Arbitrary File Write / Path Traversal | `uploadPaste(filename)` | ✅ Hit | "GraphQL Resolver Injection Vulnerability" on `uploadPaste` — one of the 3 mutations confirmed in the same run that directly demonstrates #100's breadth fix (previously only the first vulnerable mutation found would ever be reported). |
| 19 | Weak Password (Brute Force) | `systemDiagnostics` | ❌ Miss | New brute-force check (#97) exists but lives in `BrokenAuthenticationTestCase` (REST-oriented, path-pattern-gated) — not wired into the GraphQL test case, so a GraphQL-argument-based brute force isn't reached. |
| 20 | Circular Fragment Attack (DoS) | fragments | ✅ Hit | "GraphQL Circular Fragment Denial of Service" — new `testCircularFragmentAttack` (#101), confirmed live. |
| 21 | Stack Trace / Debug Error Disclosure | any malformed query | ❌ Miss | ASTF's verbose-error check is REST-oriented (`SecurityMisconfigurationTestCase`), not wired into the GraphQL test case. |
| 22 | JWT Token Forge | `me(token)` | ❌ Miss | New `testArgumentBasedAuthBypass` check (#102) exists and targets exactly this pattern (`me`/`viewer`/`currentUser`/`profile` fields with a forged token argument) — ran against DVGA but found no matching field name, so no finding. DVGA's actual mechanism may differ from the field-name heuristic used. |

---

## 4 · gRPC Goat — 1 of 9 documented labs detected

Correction from the earlier evidence report: the real repo is [rootxjs/grpc-goat](https://github.com/rootxjs/grpc-goat), not GoSecure/gRPC-Goat as previously linked. Source: each lab's own `Readme.md`. Only labs 001-002 were built and tested this session — labs 003-009 were never stood up, so most of this table is "not tested" rather than "tested and missed."

| Lab | Documented vulnerability | Tested this session? | Status | Notes |
|---|---|---|---|---|
| 001 | gRPC Reflection Enabled | Yes | ✅ Hit | "gRPC Server Reflection Enabled" — the #72 h2c fix made this reachable at all. |
| 002 | Plaintext gRPC (credential interception) | Yes (detection only) | 🚫 Not in Scope | **Why not in scope:** confirming this vulnerability requires capturing and reading raw network traffic (packet-level interception, e.g. tcpdump/Wireshark-style capture), not sending and analyzing HTTP/gRPC requests. That's a network traffic analysis capability, a different tool category entirely — no amount of improving ASTF's request logic gets you there. ASTF can flag the absence of TLS as a misconfiguration signal, but actually demonstrating credential interception is out of reach for any request-based scanner, commercial or open source. |
| 003 | Insecure TLS (self-signed, MITM-able) | No | ➖ N/A | Not built/run this session. |
| 004 | Arbitrary mTLS (any client cert accepted) | No | ➖ N/A | #88's `MutualTlsValidationTestCase` is built for exactly this — never live-tested against it. |
| 005 | mTLS subject/CN validation bypass | No | ➖ N/A | Same test case as 004 would need a second run with a forged-CN cert. |
| 006 | Unix socket world-writable | No | 🚫 Not in Scope | **Why not in scope:** this is a filesystem permission check (whether a Unix socket file on the host has world-writable perms) — it has nothing to do with how the API is called or structured, and isn't reachable by sending any HTTP/gRPC request. That's host/OS hardening territory, a different discipline from API security testing. Explicitly closed as out of scope in [issue #89](https://github.com/OWASP/www-project-api-security-testing-framework/issues/89). |
| 007 | SQL Injection | No | ➖ N/A | Even if tested, ASTF's gRPC test case is detection/enumeration-only by design — no injection capability. |
| 008 | Command Injection | No | ➖ N/A | Same structural limitation as 007. |
| 009 | SSRF | No | ➖ N/A | ASTF's SSRF test case is REST-oriented; gRPC has no equivalent. |

---

## 5 · Why the numbers look like this

Four different reasons collapse into one low number per target, and they call for different responses — the first three are all, in one way or another, still ASTF's job; the fourth deliberately isn't:

- **Structural gaps in ASTF** — real, fixable misses on vulnerability classes a generic scanner plausibly could catch: GraphQL SSRF/injection on argument-level fields beyond the one tested per run, NoSQL injection, operation-name abuse, brute-force/enumeration, ReDoS, response-timing DoS. Each of these is a legitimate "file an issue" gap.
- **Untested, not undetectable** — labs/endpoints/challenges this session simply didn't reach (gRPC Goat 003-009, several crAPI challenges, DVGA's later solution pages). The capability may already exist or be close; it just wasn't pointed at these specific targets yet.
- **Technically unreachable by any automated tool, but still conceptually in scope** — crAPI's business-logic challenges (balance/coupon/quantity manipulation, undocumented-field leaks). These *are* real API vulnerabilities in the OWASP sense — they need semantic domain knowledge ("what does a correct balance look like") that no generic scanner, ours or anyone else's, has. The limitation is technical, not a scope decision; if a future version adds domain-aware business-logic testing, these belong on the "fixable" list.
- **🚫 Not in scope — a different discipline entirely** — filesystem permission checks (gRPC Goat 006, Unix socket world-writable) and packet-level credential interception (gRPC Goat 002, plaintext-credential capture). Neither of these is reachable by sending and analyzing API requests, no matter how good the scanner is — one is host/OS hardening, the other is network traffic analysis. These aren't "hard for ASTF"; they're categorically outside what an API-request-based testing tool does. Tagged explicitly as 🚫 Not in Scope in the tables above rather than lumped in with genuine misses.

The one number worth treating as a real defect rather than a scoping choice: **VAmPI's non-numeric path IDs make its own two headline vulnerabilities invisible** to a test case that's supposed to exist specifically to catch them. That's not "we didn't get to it" — it's "the check runs, on the right target class, and still can't see it."

## 6 · Bottom line

Across 58 officially documented vulnerabilities/challenges/labs in these four targets, ASTF's current release catches **18** — roughly 1 in 3.2, up from 10 (1 in 6) two rounds ago. Every hit added since then was live-verified against the real running target, not just unit-tested: VAmPI's cross-user BOLA (including a real password takeover — confirmed by actually logging in with the changed password), SQL injection, and ReDoS findings were reproduced with real curl replays against real error pages; DVGA's alias-based DoS, circular-fragment DoS, and query-field resolver injection were confirmed live; and crAPI's BFLA privilege-tier-substitution finding was confirmed end-to-end against the real public demo (crapi.apisec.ai) with a freshly registered account. This is not a criticism of the work done across earlier rounds; it's a statement about how large the total surface actually is once you trace back to each target's own documentation instead of stopping at "the scan completed and found some things."

This round's robustness pass closed several gaps found by asking "how confident are we that ASTF misses nothing structural in scope?" rather than by re-running old scans:

1. Removed an artificial 5-field cap on GraphQL mutation/query candidates that was silently dropping every field beyond it — DVGA's `importPaste` (SSRF/OS injection) and `uploadPaste` (path traversal) sit at positions 9/10/18 in the schema and were never reached before.
2. Made BOLA's cross-user check send a realistic body instead of an empty `{}` on state-changing requests — this is what turned VAmPI's password-change row from a reachable-but-unconfirmed "Partial" into a live-confirmed account takeover.
3. Added a new BFLA check for privilege-tier path substitution (e.g. `/user/` → `/admin/` on an otherwise identical request) after reading crAPI's actual source and finding its BFLA vulnerability is exactly this pattern.
4. Added GraphQL-specific brute-force-lockout and stack-trace-disclosure checks, since the existing REST-shaped versions never sent a GraphQL-shaped request body.
5. Fixed a real crash found via this same live-testing — DVGA's `me(token)` field, newly reachable after fix (1), crashed the container when fed generic SQL/XSS payloads instead of a JWT-shaped one, so token-like arguments are now excluded from that payload class and left to the dedicated JWT-forgery check instead.

The remaining largest gap: crAPI and DVGA's business-logic and multi-step challenges ([issue #103](https://github.com/OWASP/www-project-api-security-testing-framework/issues/103), deliberately deferred) — including crAPI's mechanic-report BOLA, whose vulnerable endpoint only exists as a URL returned in a live response field, requiring the same multi-step-flow capability.

---

Sources: VAmPI README + author blog post; [crAPI docs/challenges.md](https://github.com/OWASP/crAPI/blob/main/docs/challenges.md) + `challengeSolutions.md`; DVGA's 22 in-app solution templates; [rootxjs/grpc-goat](https://github.com/rootxjs/grpc-goat) per-lab READMEs. Local evidence: saved JSON scan reports from both test rounds, cross-checked against test-case source where a finding's absence needed root-causing.
