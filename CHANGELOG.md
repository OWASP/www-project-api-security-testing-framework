# Changelog

Releases before 2.0.2 are described on the [GitHub Releases page](https://github.com/OWASP/www-project-api-security-testing-framework/releases).

## Unreleased

### Added

- **Inbound webhook signature verification check** (#192). `ASTF-API10-2023` now probes POST/PUT/PATCH endpoints whose path contains `/webhook`, `/webhooks/`, `/hooks/` or `/callback/`. It sends a benign Stripe, GitHub or Slack style event (a provider named in the path selects that shape, otherwise all three are tried) with no signature, an invalid signature, and a stale timestamp with a well-formed but invalid signature. A 2xx whose body shows the event was processed is reported as CRITICAL "Webhook Accepts Unsigned/Forged Events"; a 2xx with an empty or generic body is MEDIUM "Webhook Signature Check Not Confirmed"; 400/401/403 passes. Note that if the receiver is vulnerable, the benign event is processed and may change state on the target.

- **GraphQL query-field brute-force detection** (#117). The existing brute-force check only matched a *mutation* named like a login. An authentication gate exposed as a *query* field and not named like a login — DVGA's `systemDiagnostics(username, password, cmd)` — went undetected. A new check introspects query fields for one governed by both a username-like and a password-like argument, sends eight failed attempts, and reports a missing-rate-limiting finding (MEDIUM) if no 429/423 lockout appears. The call carries a selection set only for object-returning fields, so a scalar-returning field like `systemDiagnostics: String` is queried correctly. Discovery relies on introspection being enabled. Live-verified against DVGA: reported "No Rate Limiting on GraphQL Query-Field Authentication" for `systemDiagnostics`.

### Fixed

- **BOLA checks no longer modify or delete other users' objects by default, and find stateful BOLA** (D1, D6, D7 in the ASTF gap analysis). On `PUT`/`PATCH`/`DELETE`/`POST` endpoints the cross-user check and ID substitution sent the real method, including `DELETE` to guessed IDs `1`, `2`, `100`, `999` and `0`. The primary identity's request also went first, so on a stateful API the secondary identity found nothing left and the bug was missed. Write endpoints are now probed with a read-only `GET` on the same URL unless the new `--allow-destructive` flag (config `allowDestructive`) is set; a check that cannot run read-only is reported as INFO "Check Held Back" instead of disappearing. With the flag, the secondary identity's request is sent first. Cross-user access is CRITICAL only when the secondary identity receives the primary identity's object and an anonymous request does not; a 2xx with different content is MEDIUM "Not Confirmed". `PATCH` endpoints were sent as `GET`; they are now sent as `PATCH`.

### Behaviour changes to know about

- Without `--allow-destructive`, VAmPI's cross-user password change (`PUT /users/v1/{username}/password`) is reported as INFO "Check Held Back" instead of CRITICAL, because the password change is not sent. Add `--allow-destructive` to reproduce the account takeover against test accounts.
- A cross-user 2xx whose body does not contain the primary identity's object is MEDIUM instead of CRITICAL, and an object that is also returned without credentials is no longer reported as BOLA (ASTF-API2-2023 reports the missing authentication).

## 2.0.2 (patch)

A correctness release. No new command-line flags, no report-format changes, and exit codes keep their meaning. Every code fix below has unit tests, and the release build was checked with full scans of VAmPI, crAPI, DVGA and gRPC Goat in Docker, compared with the previous code (results are in the release pull request).

### Fixed

- **NoSQL bypass false positives** (#142, #147). The generalized bypass check from #136 reported CRITICAL bypasses on VAmPI, which has no NoSQL backend: a target that degraded mid-scan, or a create endpoint that succeeds once and then says "already exists", looked like a bypass. Failure responses are now recognized from parsed JSON, the baseline is re-checked before reporting, and a bypass is CRITICAL only if the same payload succeeds again; otherwise it is reported as MEDIUM "Possible Bypass (not reproducible)". If the target's answer to the invalid baseline changed during the scan, or the baseline got a server error instead of a rejection, the result is reported as INFO "Inconclusive" instead of being dropped.
- **GraphQL** (#140). The GraphQL suite ran once per scanned endpoint and repeated every finding; it now runs once per GraphQL URL. The circular-fragment probe, which crashes DVGA, now runs last and records whether the target recovered, so the checks after it no longer run against a dead server; the wait for recovery is bounded in time. Database errors leaked by resolvers (for example `sqlite3.OperationalError` with the SQL text) are now detected.
- **Soft-404 detection hid real endpoints** (#149). Short bodies and small insertions were treated as the catch-all page; very short bodies now have to match exactly.
- **Basic Auth** (#150). The authenticator replaced explicit `Authorization` headers, retried without limit and could send credentials to another host after a redirect. It now keeps explicit headers, retries once, and only for the target host.
- **SSRF false CRITICAL** (#151). An API that echoed the probe URL matched the probe's own indicator. Payload echoes are now removed before matching, a response identical to the baseline is ignored, and the endpoint's normal response is checked again before reporting, so content that changes during the scan (for example posts created by other checks) is not mistaken for fetched metadata. The evidence names the indicator that matched. A match in a non-2xx response is reported as MEDIUM "Possible Server Side Request Forgery" instead of CRITICAL.
- **ReDoS false HIGH** (#152). Any network error, including the scan's own timeout, was reported as a regex hang. Only a timeout right after a healthy baseline counts now.
- **Cookie store race** (#153). The cookie store was not thread-safe under the scanner's virtual threads.
- **Progress line** (#154). Tasks abandoned at the timeout were counted as completed, so an unfinished scan showed 100%. They are now reported separately.
- **Reports** (#155). Report files are written readable by the owner only, and a report path that is a symlink is replaced instead of written through. Session cookie values in cookie findings and token-like parameters in redirect `Location` evidence are masked.
- **Documentation.** The example configuration files used keys the loader does not read; they are rewritten and say that credentials come from command-line flags. The README CI example failed on any finding and passed silently on a scan error; it is fixed and pins the release. Build-from-source steps explain the JDK 21 requirement and the "class ASTFCli not found" error (discussion #46). Stale test counts are removed.

### Also new since 2.0.1

These were merged to main after the 2.0.1 release and ship for the first time in 2.0.2: behavioural SQL injection detection (#124), JWT none-algorithm check with the token's real claims (#126), unauthenticated probes no longer carrying credentials (#130), dependency security updates for jackson-databind and log4j (#131, #138), soft-404 screening of guessed paths (#134), NoSQL bypass detection beyond login fields (#136) and request bodies in configuration endpoints (#137).

### Behaviour changes to know about

- Report files are now `rw-------` on filesystems that support it.
- An SSRF indicator in a non-2xx response is reported as MEDIUM "Possible", not CRITICAL.
- A NoSQL bypass that does not reproduce is reported as MEDIUM, not CRITICAL, and a result taken while the target's behaviour changed is reported as INFO. Confirming a bypass sends the payload once more, only when a bypass is about to be reported.
- The progress line can now show fewer than 100% completed when a scan hits its timeout.

### Known limitations

- Some findings depend on the target's state during the scan. On VAmPI, other checks can delete the user `name1` before the SQL injection check reaches `DELETE /users/v1/name1`, so that finding occasionally does not appear; this happens with 2.0.1 as well.
- A target that cannot be reached is not reported as a scan error: the scan exits 1 with the generic fallback findings. Check the log for connection errors.
- On slow targets such as crAPI, ReDoS findings can still appear on a different endpoint from one run to the next.
- Planned for 2.1.0, not in this release: unauthenticated probes that still carry the scan's credentials in some checks, credentials sent to another host on redirects or to a spec URL named by Swagger UI, and auth-path detection that matches substrings.
