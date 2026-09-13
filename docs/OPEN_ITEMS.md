# Open Items — Bugs Fixed and Enhancements Tracked

A single place to see what got fixed, what got investigated and ruled out, and what's queued up as an enhancement request — separate from `docs/TRACEABILITY.md`, which tracks a different thing entirely (what ASTF detects on a target, not ASTF's own code health).

---

## 1 · Bugs fixed

| # | Bug | Severity | PR | Status |
|---|---|---|---|---|
| 1 | `HttpClient` always attaches the configured bearer token/API key as a default header, even to requests a test case built specifically to have zero credentials — breaks the "endpoint actually requires auth" baseline used by `testMissingAuthentication` and all 4 JWT forgery sub-attacks (`testJwtNoneAlgorithm`, `testJwtKidPathTraversal`, `testJwtAlgorithmConfusion`, `testJwtJkuProcessing`). Caused a false positive (`Missing Authentication Controls` on properly-protected endpoints) and silently blocked the real-claims JWT-none finding from PR #126 from ever firing via the CLI. | High | [#130](https://github.com/OWASP/www-project-api-security-testing-framework/pull/130) | Open, not merged |
| 2 | 6 open GitHub Dependabot alerts against `pom.xml` — 2 High + 3 Moderate `jackson-databind` CVEs, 1 Moderate `log4j-api` CVE. Fixed via version bumps (`jackson-databind` 2.15.3 → 2.22.2, `log4j` 2.25.4 → 2.25.5). Confirmed neither Jackson High-severity CVE was actually exploitable in this codebase (no polymorphic/default typing used anywhere), patched anyway. | High / Moderate | [#131](https://github.com/OWASP/www-project-api-security-testing-framework/pull/131) | Open, not merged |

Both PRs: full test suite green, live/smoke-verified, not merged — open for review.

---

## 2 · Investigated and ruled out (retraction, for transparency)

**"VAmPI endpoint-drop bug"** — an earlier pass through this session concluded that `Scanner` was silently dropping 3 of 14 discovered endpoints (including the two BOLA-vulnerable and one SQLi-vulnerable path documented in `docs/TRACEABILITY.md` rows 1–3) from the actual test-execution loop, based on a scan log showing only 7 of 14 endpoints appearing in `Executing ...` lines despite the scan reporting "224/224 tasks completed."

**Re-investigated with a clean, isolated, single live run and found this was wrong.** A fresh VAmPI instance, one scan, no concurrent runs sharing log output: all three previously-"missing" endpoints (`GET /users/v1/name1`, `GET /books/v1/bookTitle29`, `PUT /users/v1/name1/password`) tested normally.

The real mechanism: the original run's log contains `WARN Scanner - Scan interrupted or timed out before completion: null` at exactly the 30-minute mark (`ScanConfig`'s default `timeoutMinutes = 30`). VAmPI's vulnerable container — a single-threaded Flask dev server — wedges completely when hit by the `RegexDosTestCase` payload (confirmed separately, reproduced 3 times this session, ~105%+ CPU, unresponsive to all requests until `docker restart`). That wedging crushed throughput through the `--threads`-bounded concurrency semaphore for long stretches. When the overall 30-minute scan timeout fired, `Scanner` calls `executor.shutdownNow()`, which cancels every still-queued (not-yet-acquired-a-permit) task. Each cancelled task's `concurrencyLimiter.acquire()` throws `InterruptedException`, which is caught, increments `completedTasks`, and returns — without ever reaching the test case's own `logger.info("Executing ...")` line. That's why the "completed" counter still reached 224/224 while the actual meaningful coverage was much smaller. Which specific endpoint×test-case pairs get cancelled this way is essentially random (whatever's still queued at the 30-minute mark), not deterministic — which is exactly why the clean re-run (less total wedged time) got through more of the matrix and happened to include all three previously-"missing" paths.

**Not a discovery/dedup/endpoint-list bug.** `PathTemplateResolver` and `Scanner`'s endpoint-list handling both work correctly — confirmed by direct code read and live test. No PR needed. Full writeup: `RETRACTED_endpoint_drop.md` (local scratch notes, not part of this repo).

**Real, much smaller gap surfaced by this investigation** (see enhancement #3 below): when a scan does legitimately hit its timeout against a slow/unresponsive target, there's no record of *which* endpoint×test-case combinations got silently abandoned — just a generic warning. Worth a small follow-up; not urgent, not a correctness bug.

---

## 3 · Enhancement requests tracked

| # | Request | Source | Notes |
|---|---|---|---|
| 1 | **GitHub Action** — an official GitHub Action (or Docker image) to run ASTF in CI, instead of the current "download/build the jar" workflow. | [#129](https://github.com/OWASP/www-project-api-security-testing-framework/issues/129) | Reporter is willing to submit a PR but would need guidance. Scoping needed: composite action wrapping the jar vs. a published Docker image vs. both. Note `integrations`/`integrations` packages already handle GitHub Actions *CI-detection* (reading `GITHUB_ACTIONS` env, PR context) — this request is the inverse direction, *being* runnable as an Action, a different piece of work. |
| 2 | **Logging of evidence** — a CLI option to log every HTTP request/response the scanner makes (to JSON or HAR), so findings can be independently verified without a proxy like OWASP ZAP. Reporter's concrete pain point: a `Missing Authentication Controls` finding they couldn't reproduce because ASTF doesn't expose the actual request it sent. | [#127](https://github.com/OWASP/www-project-api-security-testing-framework/issues/127) | Reporter can't implement it themselves. Directly relevant to this session's own work — the `HttpClient` default-header bug fixed in PR #130 is exactly the kind of thing full request/response logging would have surfaced immediately instead of requiring source-level investigation. Worth prioritizing; ties into `Finding.setEvidence(...)`, which already exists but currently only captures a status-code summary, not the raw exchange. |
| 3 | **Scan-timeout task visibility** *(new, surfaced by this session's investigation, not yet filed as an issue)* — when `Scanner`'s overall `--timeout` fires against a slow/hung target, tasks still queued behind the concurrency semaphore get silently cancelled with no record of which endpoint×test-case pairs were abandoned. The existing `WARN "Scan interrupted or timed out before completion"` log doesn't say what got skipped. Low severity (the scan still completes and reports whatever it found), but worth a small fix: log or report the specific abandoned (endpoint, test case) pairs so a user re-running against a slow target knows what to re-check, rather than silently getting partial coverage that looks identical to a clean run in the summary output. |

No PRs opened for these — enhancements need scoping/design discussion before implementation, per this project's contribution workflow (`docs/TRACEABILITY.md` intro: pick a concrete scoped gap → file an issue → implement → live-verify → PR).
