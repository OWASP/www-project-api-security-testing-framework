# ASTF release plan: 2.0.2, 2.1.0, 2.2

Status: draft for maintainer review. Date: TBD. Everything below, including the decision record and the refused list, is a proposal until the maintainers sign off. Nothing here is a committed scope or date.

This plan covers three releases. It is built from the v2.1.0 milestone (#127, #129, #120), the Phase 6 roadmap in `index.md`, `docs/OPEN_ITEMS.md`, the open issues and PR review comments, and a code audit of `main` at commit 172f701. Each audit finding was checked by reading the code and, where noted, by running it. None of the fixes below have been implemented yet, and the effort sizes are estimates. Items that could not be verified are marked.

## What ASTF is and is not

ASTF is a command line tool. A user gives it a target, optional credentials and an optional endpoint list. It sends requests and writes report files (JSON, HTML, SARIF, XML). It ships as a jar and, from 2.1.0, also as a container image and a GitHub Action.

The core is local and file-based: no database, no accounts, no hosted component, and no state between runs other than files the user asks for. A local report viewer that reads those files is acceptable if users need one (see 2.2). What the project does not take on is anything that has to keep running for other people, or needs a database behind it. Nothing in this plan changes that.

One project rule applies to every item: a change must never cause an endpoint or test case to be skipped. When a safety control holds a check back, the report lists what did not run and why.

## How we decided what goes in

The goal is a scanner a security engineer can stand behind in a report, so correctness comes before features. Every candidate item had to pass three questions:

1. Does it make a result ASTF prints more true, or stop ASTF leaking something it was given? If yes, it is a fix and goes first.
2. Does a real user or reviewer ask for it (an issue, a review comment, a failure seen in live testing)? If not, it waits.
3. Can it be built and tested locally, without a hosted service or a database? If not, it is out of scope.

## Decision record: what we keep, what we defer, what we refuse

These are proposed decisions for the maintainers to confirm or change.

### Good for us, keep

- Fixing wrong results before adding anything (all of 2.0.2).
- Honest scan status: a timed-out or errored scan says so, lists what did not run, and exits with its own code.
- Unauthenticated probes that are actually unauthenticated.
- Evidence logging with redaction on by default (#127) and the GitHub Action with a container image (#129).
- Stable finding fingerprints and deterministic report order. These are small, and they unlock diffing two scans and a later suppression file.
- The scope allowlist. It is small and prevents credentials going to hosts outside the target.
- Refusing unknown config keys with a clear error. It is cheap and stops users trusting settings that do nothing.
- Release hygiene a company will check: a CycloneDX SBOM, published checksums, and a documented vulnerability reporting path.

### Over-engineering for now, deferred or cut down

| Idea | Decision | Reason |
|---|---|---|
| Per-check impact tagging and a full `--max-impact` gate | Defer to 2.2 | Classifying all 16 checks is a judgment call, and marking a destructive check as read-only is worse than having no flag. Ship only the scope allowlist now. |
| Target health circuit breaker | Cut down | Start with a total call timeout and wiring the existing `--max-rps` setting. Add a breaker only if live use shows it is still needed. |
| A general redaction framework (entropy detection, plugin rules) | Cut down | Redact by header name, cookie, query parameter, JSON key, and the exact values of the configured secrets. Nothing more. |
| A per-check state machine (queued, running, ran, errored, abandoned) | Cut down | Keep counts and a list of what did not run and why. |
| Nightly traceability regression in CI | Script first | A compose file and a script that diffs against the matrix, run by hand and before each release. Add the nightly job only if it earns it. |
| Plugin interface for custom checks | Defer to 2.2, after prerequisites | The `TestCase` contract exposes mutable internals and there are 64 hand-written finding constructors. A stable context object and a finding builder have to exist first. |
| Aggregated reporting | Keep, presentation only | Group findings with one root cause and list every endpoint. Nothing is skipped. |
| Baseline and suppression file | Defer to 2.2 | Needs the 2.1.0 fingerprint first. |
| Local dashboard or report viewer | Could, 2.2 | Start by improving the existing HTML report (filter, group, sort). If a separate viewer is still needed, it binds to 127.0.0.1 only, reads the existing JSON or SARIF files, has no database and no write endpoints, and is optional. Scan results contain secrets, so a local web server needs the same care as any other attack surface (DNS rebinding, CSRF). |

### Refused: not part of this project

A hosted or multi-user web service, a shared findings database, accounts, a scheduler, distributed workers, a plugin marketplace, automatic remediation, AI-based triage of findings, a built-in intercepting proxy, and a scoring engine that replaces the OWASP categories. Each needs something running for other people or a larger team, and none is needed to be the reference scanner for this problem. A local, optional report viewer is not on this list. Thin output files for other tools (for example JUnit XML or a DefectDojo import file) are acceptable. Calling Jira or DefectDojo APIs is acceptable only as a small optional module.

## 2.0.2: correctness and credential handling (patch, no new features)

A patch must be small diffs nobody has to think hard about, and it must not change which checks run. Each row has a test that fails before the fix. Rows marked "ran" were reproduced with a scratch program.

| # | Problem | Where | Fix |
|---|---|---|---|
| 1 | The soft-404 detector can suppress real endpoints. `(int)(shortest * 0.95)` truncates, so bodies of 2 to 19 characters tolerate one differing character and 1-character bodies always match. The length floor of 8 lets a baseline with up to 8 inserted characters count as identical (`{}` vs `{"a":1}`, `[]` vs `[{"id":1}]`). In discovery a wrong suppression removes the endpoint from the scan. Ran. | `SoftNotFoundDetector.java:379, 397`; call sites `EndpointDiscoveryService.java:359, 419`, `SecurityMisconfigurationTestCase.java:224`, `BrokenFunctionLevelAuthorizationTestCase.java:205` | Drop the floor of 8. Require `longest - shortest <= longest / 50` and `longest - (prefix + suffix) <= longest / 20`. Tests for 1, 2 and 19 character pairs and the insertion cases. Log at INFO when a hit is suppressed. |
| 2 | The Basic Auth authenticator replaces an explicit `Authorization` header on a 401 and retries with no host check and no retry limit. With `--username` set, forged-JWT probes are re-sent as the real user. A target that always answers 401 produced 21 requests. Ran. | `HttpClient.java:729-738` | Return null if the request already carries `Authorization`, retry once, and only for the target host and port. |
| 3 | SSRF can report CRITICAL on an API that only echoes its input. The indicator `computeMetadata` appears inside the probe payload itself. | `ServerSideRequestForgeryTestCase.java:42, 53, 103, 153, 209-216` | Require a 2xx, remove the payload text from the body before matching, compare with a baseline of the same shape. |
| 4 | `RegexDosTestCase` turns any `IOException` into a HIGH ReDoS finding. A scan-timeout interrupt or a network error is reported as a hang. | `RegexDosTestCase.java:97-140` | Treat only `SocketTimeoutException` as the signal, re-probe the baseline after a failure, return no finding if the thread was interrupted. |
| 5 | The cookie store is an unsynchronised `HashMap` used from many virtual threads. | `HttpClient.java:77, 743-781` | `ConcurrentHashMap` with `CopyOnWriteArrayList`. |
| 6 | Reports contain raw session cookies and `Location` values in evidence and are written world-readable. | `BrokenAuthenticationTestCase.java:944-976`, `UnsafeConsumptionOfApisTestCase.java:219`, the four generators | Cheap half only: mask `Cookie` and `Set-Cookie` values in evidence and create report files with owner-only permissions. The full redactor ships with #127. |
| 7 | Dependabot alerts #11 and #12 (jackson-databind 2.22.2 to 2.22.3). | `pom.xml` | Done: merged as PR #138 on 19 October. |
| 8 | README build steps confuse newcomers (discussion #46, "class ASTFCli not found"). | `README.md` | Clarify the build and run steps. |

Also in 2.0.2: correct `docs/OPEN_ITEMS.md` on the scan timeout. Every task is a live virtual thread parked in the semaphore, not a queued job, and tasks interrupted mid-request are also counted as completed.

## 2.1.0: trustworthy output and the committed features

Priority is marked must, should or could. If capacity runs short, cut from the bottom of this list upward and never cut a must.

### Must

**#127 Evidence logging.** An opt-in flag that records each request and response. `HttpClient` has eight request paths, all built from one base client, so one OkHttp application interceptor and one network interceptor on the base builder cover all of them, including the no-auth client and the Basic Auth retry the issue reporter could not see. Output is JSON Lines as the canonical file with a HAR export for ZAP and browser tools. Secrets are redacted by default using the narrow redactor described above, including the exact configured secret values. `--evidence-include-secrets` turns that off. Bodies are capped (start at 64 KB) with a truncation marker, and files are owner-only. Each exchange carries the id of the check that produced it.

**#129 GitHub Action and container image.** A Dockerfile, a published image, an `action.yml`, and SARIF upload. Neither integration package is reachable from the shipped jar today (`CICommand` is not registered), so the Action calls the main CLI and does not depend on that code. Before this ships, add `--fail-on <severity>`. Today any finding, including INFO, exits 1.

**#120 NoSQL breadth.** PR #136 merged on 19 October. #120 stays open until the generic detection is live-verified: crAPI row 12 has not been re-verified and may remain a miss. A full scan of VAmPI after the merge produced CRITICAL false positives on `/users/v1/login` (issue #142), so that fix comes first.

**Honest scan status.** Add a status and the list of checks that did not run to the result, show both in all four report formats and the console summary, and exit with a distinct code (proposed: 3). Stop printing "N/N tasks completed" when tasks were interrupted. SARIF currently hardcodes success. Because exit codes affect CI users, `--fail-on` defaults to today's behavior and the change is listed under "behavior changes" in the release notes.

**Unauthenticated means unauthenticated.** No-auth variants for the checks that claim "without authorization" but carry credentials: BFLA admin-path and method-escalation probes, "publicly accessible" debug, documentation and shadow-version probes, anonymous-attacker checks (brute force, user enumeration, NoSQL auth bypass), and the mTLS comparison. Findings that cannot be shown to be unauthenticated say "reachable with the configured credentials" at a lower severity. Also the cross-user BOLA identity: a request path that applies only the supplied identity, so the primary API key and cookie do not ride along.

**Credentials stay on the target.** Host pinning: when a request goes to a host other than the target (a redirect, a spec URL named in Swagger UI HTML), strip every credential header and still make the request, so discovery is not reduced. Make `followRedirects` read its config value. Add the scope allowlist.

**Checks must not disappear.** Match auth and 2FA paths by whole path segment so `/tokens` and `/discount-codes` keep the missing-auth and JWT checks. Resolve OpenAPI effective security as the operation value, else the root value, else true.

**Configuration that does what it says.** Reject unknown config keys with a clear error. Fix the README and examples to match what the parser reads. Seven documented settings (`requestDelayMs`, `maxRequestsPerSecond`, `followRedirects`, `validateCertificates`, `excludePatterns`, `maxFindings`, `excludeSeverities`) are never read; implement each or remove it from the docs.

**Release hygiene.** CycloneDX SBOM, checksums, and a vulnerability reporting path in `SECURITY.md`.

### Should

**Stable finding identity.** A fingerprint from check id, rule, method, normalised path and host, replacing the random UUID, plus a confidence field and deterministic report ordering.

**Aggregated reporting.** Group findings that share a root cause (the same missing headers or wildcard CORS on many endpoints) into one entry listing every affected endpoint. The GraphQL suite currently runs once for every non-GraphQL endpoint and repeats its findings; give it a scan-wide memo, not an early return. An earlier claim of "91 findings from crAPI, mostly repeats" could not be reproduced because the source reports were missing, so measure again before citing a number.

**Endpoint dedupe and URL joining.** One URL join helper to stop `http://host//path`, and `equals`/`hashCode` on endpoints with tests that prove no real endpoint is removed.

**Silent errors.** 71 of 77 catch blocks in the test cases log at debug and continue, so a broken check looks like a clean scan. Count checks that errored and show the count and the first few causes in the report.

**Locale safety.** 92 calls to `toLowerCase()` or `toUpperCase()` without a locale. Use `Locale.ROOT` and run the suite once with `-Duser.language=tr`.

**Remaining soft-404 sites and fallback confidence.** `OPEN_ITEMS.md` #4 and #5.

### Could

**Traceability regression script.** A compose file and a script that start the four lab targets, run ASTF and compare detected rows with `docs/TRACEABILITY.md`. Generate the test count and matrix totals in docs from the build.

**Target protection.** A total call timeout and `--max-rps` wired to the existing field. One hung target used the full 30 minute budget three times during live testing.

**Quality gates.** JaCoCo, a Dependabot configuration for Maven and GitHub Actions, a second Java version in CI, real-`HttpClient` tests for behavior inside `HttpClient`, and tests for `ASTFCli`, which has none.

**GitHub integration code fixes.** `GITHUB_TOKEN` is set as the default `Authorization` header sent to the target, a pull request number is cut by one character, and every pull request in an org repo is treated as a fork. Fix these only when that code is wired up, since it is not reachable today.

### Close with care

DVGA rows 19 and 21 describe gaps for which code exists (`testLoginMutationBruteForce`, `testStackTraceDisclosure`), but a live check of both did not complete because the DVGA container crashed during the run. Re-run them against a stable DVGA before closing #117 and #118 or editing the matrix. The crash is worth its own investigation.

## 2.2: reach, after the core is trustworthy

- Spec-first discovery: full OpenAPI 3 (parameters, request bodies, security schemes, `$ref`), a `--spec` flag for a local file or any URL, and Postman collection import. Today a spec is probed at ten fixed paths and only paths and methods are read. crAPI needed its Postman collection converted by hand.
- Findings baseline and suppression file, with a reason and an expiry, using the 2.1.0 fingerprint.
- Per-check impact tagging and `--max-impact`, with held-back checks listed in the report.
- Login-flow support so a user configures a credential sequence once.
- Multi-step flows (#103), starting with chained requests where a value from one response feeds the next.
- A plugin interface for custom checks, after a stable context object and a finding builder exist.
- A local report viewer, only if the improved HTML report is not enough (guardrails in the decision record).
- The testable subset of the OWASP LLM Top 10 from the roadmap.
- The remaining DVGA and crAPI enhancement issues (#115, #116, #119, #121) as each is scoped.

## Release criteria

- 2.0.2: every row has a test that fails before the fix, the full suite passes, and the release notes list behavior changes (there should be none beyond the fixed results).
- 2.1.0: a timed-out scan exits with the incomplete code and lists what did not run, a test that searches evidence files finds none of the configured secrets, the Action runs end to end in a sample repository, no open high-severity Dependabot alerts, and each change is live-verified against a real target before the matrix is updated, as for every change in this project.
- 2.2: the same live verification for each feature.

## Open decisions for the maintainers

1. Whether 2.0.2 ships now that PRs #136 and #138 are merged, or waits for the fix in issue #142.
2. The incomplete-scan exit code, and whether `--fail-on` stays off by default.
3. Uniform CRITICAL for every confirmed NoSQL bypass (decided in the PR #136 discussion) versus a confidence field in 2.1.0. Issue #142 is a reason to revisit this.
4. How much of 2.1.0 two maintainers can carry. The cut order is stated above, from the bottom of Could upward.

## Sources

Issues #103, #114 to #123, #127, #129. PRs #130, #131, #134, #136, #137, #138 and their review comments, including the automated review comment on #134. Discussions #41 and #46. `index.md` roadmap, `docs/OPEN_ITEMS.md`, `docs/TRACEABILITY.md`, and a code audit of `main` at commit 172f701.
