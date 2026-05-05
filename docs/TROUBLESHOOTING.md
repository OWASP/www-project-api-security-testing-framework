# Troubleshooting Guide

## Adjusting Log Levels

ASTF uses **Log4j 2** for all logging. The configuration file is at:

```
src/main/resources/log4j2.xml
```

By default the framework logs at `INFO` level to both the console and a rolling file (`astf-scan.log`). To get more detail during endpoint discovery or test execution, change the ASTF logger level to `DEBUG`:

```xml
<!-- src/main/resources/log4j2.xml -->
<Logger name="org.owasp.astf" level="DEBUG" additivity="false">
    <AppenderRef ref="Console"/>
    <AppenderRef ref="File"/>
</Logger>
```

Rebuild after changing the XML:
```bash
mvn package -DskipTests -q
```

### Log level guide

| Level | When to use |
|---|---|
| `WARN` | Production / CI — only problems |
| `INFO` | Default — scan progress and finding summaries |
| `DEBUG` | Diagnosing discovery issues or test failures |
| `TRACE` | Deep HTTP request/response tracing |

The rolling log file (`astf-scan.log`) rotates at 10 MB and keeps the last 5 compressed archives. Check it after a scan for the full trace:

```bash
cat astf-scan.log | grep "ERROR\|WARN"
```

---

## Common Errors

### `maven-resources-plugin:3.4.0` not found

```
Could not find artifact org.apache.maven.plugins:maven-resources-plugin:jar:3.4.0
```

**Cause:** The version of Maven on the runner uses `3.4.0` as its default, which has not been published to Maven Central.  
**Fix:** The `pom.xml` already pins `maven-resources-plugin` to `3.3.1`. Ensure you are building from the latest `main` branch.

---

### Exit code 2 — scan error

```
Error: Process completed with exit code 2.
```

**Cause:** Bad configuration, unreachable target, or missing required flags.  
**Fix checklist:**
1. Confirm the target URL is reachable: `curl -I https://api.example.com`
2. Confirm `-u` (URL) or `-c` (config file) is provided
3. Run with `-v` to see verbose error output
4. Check `astf-scan.log` for the full stack trace

---

### No endpoints discovered

```
INFO  EndpointDiscoveryService - Discovered 0 unique endpoints
```

**Cause:** The target may require authentication before returning valid responses, or uses non-standard paths.  
**Fix options:**
- Provide a Bearer token: `--token "YOUR_JWT"`
- Disable discovery and specify endpoints manually in a config file
- Set `DEBUG` logging to see which paths were probed and what status codes were returned

---

### `UserDetailsService returned null` on crAPI login

**Cause:** crAPI requires email verification before the first login.  
**Fix (local Docker install):** Open `http://localhost:8025` in a browser, find the verification email, and click the link.  
**Fix (public demo):** Use a Mailinator or similar inbox for the registered email address.

---

### `Unmatched arguments: 'scan'`

```
Unmatched arguments from index 0: 'scan'
```

**Cause:** The CLI does **not** have a `scan` subcommand — all flags are top-level.  
**Fix:** Remove the word `scan`:
```bash
# Wrong
java -jar astf.jar scan -u https://api.example.com

# Correct
java -jar astf.jar -u https://api.example.com
```

---

### OkHttp SSL/TLS errors

```
javax.net.ssl.SSLHandshakeException: PKIX path building failed
```

**Cause:** The target uses a self-signed or corporate CA certificate.  
**Fix:** Import the certificate into the Java trust store, or disable TLS validation in the config file (testing only):

```yaml
execution:
  validateTls: false
```

---

## Release Troubleshooting

### Release workflow did not trigger after pushing a tag

**Cause:** The tag may not match the `v*` pattern, or the workflow file wasn't on `main` when the tag was pushed.  
**Check:**
```bash
git tag -l          # list all tags
git ls-remote --tags origin   # confirm tag reached remote
```
The `release.yml` workflow only fires on tags pushed to the remote — a local tag alone won't trigger it.

---

### Release workflow failed at the test step

The release workflow runs the full test suite before building the JAR. If any of the 224 tests fail, the release is aborted — no JAR is published and no GitHub Release is created.  
**Fix:** Check the failed Actions run for the test failure, fix it on `main`, delete the tag, and re-tag:

```bash
# Delete tag locally and remotely, then re-push after the fix
git tag -d v1.0.0-beta
git push origin :refs/tags/v1.0.0-beta

# After fixing and merging to main:
git tag v1.0.0-beta
git push origin v1.0.0-beta
```

---

### JAR not attached to the GitHub Release

**Cause:** The `softprops/action-gh-release` action requires `contents: write` permission. This is set in `release.yml`, but if the workflow was modified, the permission may have been removed.  
**Check:** Open the failed Actions run → look for a `403 Resource not accessible by integration` error in the "Create GitHub Release" step.  
**Fix:** Ensure `release.yml` contains:
```yaml
permissions:
  contents: write
```

---

### Downloaded JAR won't run — `UnsupportedClassVersionError`

```
java.lang.UnsupportedClassVersionError: ... (class file version 65.0)
```

**Cause:** The JAR was compiled with Java 21 but you are running it with Java 17 or older. Class file version 65.0 = Java 21.  
**Fix:** Install Java 21+:
```bash
java -version   # must show 21 or higher
```

---

## Reporting Issues

This is a **beta release** — we actively want your feedback.

### Bug Reports
Use the [Bug Report template](../.github/ISSUE_TEMPLATE/bug_report.md). Include:
- ASTF version (`java -jar astf-v1.0.0-beta.jar -V`)
- Java version (`java -version`)
- The exact command you ran (redact any tokens)
- Relevant output from `astf-scan.log`

[→ Open a bug report](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=bug_report.md)

### Feature Requests
[→ Open a feature request](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=feature_request.md)

### Test Case Enhancements
If a detection is missing or producing false positives:  
[→ Open a test case enhancement](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=test_case_enhancement.md)

### Documentation Improvements
[→ Open a documentation issue](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=documentation_improvement.md)
