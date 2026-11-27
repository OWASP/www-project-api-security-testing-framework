# Roadmap: becoming a top-tier open-source API security tester

Status: draft proposal for maintainer review. Nothing here is a committed scope or date. The release-by-release plan lives in `docs/RELEASE_PLAN.md`; this document explains the architecture reasoning behind it and what would have to be true for ASTF to be counted among the best tools in its category.

## The goal, stated so it can be measured

"Top 2 or 3" is a ranking that someone else assigns, and we have not benchmarked other tools, so we do not aim at a rank. We aim at being the best open-source, local, CI-native tester for API authentication and authorization problems, with findings a developer can verify in minutes. That category is winnable by a small team. Broad fuzzing, manual testing depth and managed hosted scanning are other tools' strengths, and we do not compete there.

Success is measured by things we can count:

| Measure | How we know |
|---|---|
| Detection depth on public labs | The traceability matrix (`docs/TRACEABILITY.md`), checked nightly in CI against the live labs. |
| Trust | No findings on a deliberately secure target (the secure VAmPI variant) and no run-to-run variance on the same target. |
| Verifiability | Every finding carries the request, the response and a reproduction command. |
| Adoption | A new user gets a useful scan from the container image or GitHub Action in minutes. |

We do not publish a target number. The matrix is the source of truth and every number in it was live-verified.

## Where the architecture is today

The pipeline is a command line, a scanner core that runs every check against every endpoint on virtual threads, one HTTP client that all traffic goes through, sixteen test cases, and four report formats.

**What is sound**
- One HTTP client is the only way requests leave the tool. Credentials, redaction, proxying and evidence logging each have one place to live.
- The `TestCase` interface is small, so contributors can add a check without understanding the rest.
- The rule that a change must never cause a check or endpoint to be skipped, and a public matrix that lists the misses, are the project's real assets.

**What a month of live testing showed is structurally weak**
1. **Checks share no scan state.** A check receives one endpoint and the HTTP client, nothing else. There is nowhere to keep named identities, values captured from earlier responses, or a record of what has already been tested. This is why the GraphQL suite repeated for every endpoint and needed a per-client memo, and why multi-step flows (#103) cannot be written as a check today.
2. **No model of target health.** Our own checks degraded or crashed labs mid-scan (DVGA exited, VAmPI hung on its regex), later checks ran against a dead target, and the report said nothing. Counts varied between identical runs.
3. **Findings are not verifiable objects.** There is no confidence level, no distinction between confirmed and suspected, and no reproduction command. Two false-positive classes (NoSQL bypass, ReDoS) came from treating "the response looked different" as proof.
4. **Input is narrow.** There is no OpenAPI import, so real APIs need hand-built endpoint files. Request bodies in configuration only arrived recently.
5. **Configuration and docs drifted.** Several documented keys did nothing, and the progress line reported abandoned work as complete.
6. **The most valuable test is manual.** Running the four labs and comparing results is what caught the problems above, and it is not yet in CI.

## Priorities

**P0: make results trustworthy (2.0.2 and early 2.1.0)**
- The correctness and credential fixes in the release plan.
- An honest scan status: which checks ran, which did not and why, with a distinct exit code when a scan is incomplete.
- A target-health breaker: when the target stops answering, record it, pause, and say so in the report instead of continuing silently. This must not skip checks; it delays them and reports.
- Lab regression in CI. A nightly job starts the four labs, runs the scanner and compares the findings with the expected hits in the matrix. A secure-target run with zero expected findings guards against false positives. This turns the matrix from a document into a test.

**P1: make it easy to adopt (2.1.0)**
- OpenAPI import (`--spec`) with example values and the document's own security requirements.
- Container image and GitHub Action, with pinned versions and published checksums.
- Evidence logging with redaction on by default.
- Stable finding fingerprints and a baseline or suppression file, so teams can adopt the tool on an existing API without drowning in known findings.

**P2: make it capable (2.2)**
- A scan context shared by checks: named identities, a graph of resources discovered from responses, and the target-health state. This is the one breaking change to the internal check interface, and it is cheaper before more community checks depend on it.
- Chained requests (#103) on top of that context.
- An authorization matrix as the flagship check: identities by resources by roles. This builds on the two-identity object-level check that is already the tool's strongest area.
- Re-verify the other JWT variants (algorithm confusion, key-URL and key-ID abuse) against a target where each is actually exploitable, and report the result whichever way it comes out.

**P3: ecosystem (after P2)**
- A thin wrapper so AI agents can run scans and read findings. It needs evidence logging and honest scan status first, so that an agent can verify a finding and can tell when a scan did not finish. Scan output includes text from the target, so anything that reads it must treat it as untrusted.
- Declarative checks, so contributors who do not write Java can add simple ones. Worth doing only if contribution volume justifies the maintenance.

## What we will not build

A hosted multi-user service, a shared findings database, accounts, a scheduler, distributed workers, a plugin marketplace, automatic remediation, AI triage, a built-in intercepting proxy or a proprietary scoring engine. The core stays local and file-based. An optional local report viewer is possible later and must bind to the loopback interface only and read the existing report files.

## Risks and trade-offs

- **Capacity.** A small maintainer team cannot do P0 to P2 at once. P0 and P1 are what make the tool trustworthy and usable; P2 is what makes it competitive. If something has to give, P3 goes first.
- **The scan-context change breaks the internal check interface.** The cost grows with every new check, so it should land early in 2.2.
- **Claims.** Every public number should come from the CI lab run and not from a manual run. A single overstated claim costs more than any feature gains.
- **Comparisons.** We have not benchmarked other tools. Statements about them in this repository should be limited to what their own documentation says, with a link.

## Open decisions for the maintainers

1. Whether the scan-context change lands in 2.1.0 or 2.2.
2. Whether lab regression in CI is a hard gate or an advisory job at first.
3. Whether a confidence level on findings is added in 2.1.0 or waits for the scan context.
4. How much of P1 two maintainers can carry in one release.
