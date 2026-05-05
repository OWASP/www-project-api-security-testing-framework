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
**Fix:** The `pom.xml` already pins `maven-resources-plugin` to `3.3.1`. If you see this error, ensure you are building from the latest `main` branch.

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

**Cause:** The target may require authentication before it returns any valid responses, or uses non-standard paths.  
**Fix options:**
- Provide a Bearer token: `--token "YOUR_JWT"`
- Disable discovery and specify endpoints manually in a config file
- Set `DEBUG` logging to see which paths were probed and what status codes were returned

---

### `UserDetailsService returned null` on crAPI login

**Cause:** crAPI requires email verification before the first login. The verification link is sent to the mailbox configured in its mail service (port 8025 on local installs).  
**Fix (local Docker install):** Open `http://localhost:8025` in a browser, find the verification email, and click the link before logging in.  
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
**Fix:** Import the certificate into the Java trust store, or for testing only, disable TLS validation via the config file:

```yaml
execution:
  validateTls: false
```

---

## Reporting Issues

This is a **beta** release — we actively want your feedback.

### Bug Reports

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:
- ASTF version (`-V` flag output)
- Java version (`java -version`)
- The command you ran (redact any tokens)
- The full error from `astf-scan.log`

Open a bug report: [github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=bug_report.md](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=bug_report.md)

### Feature Requests

Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md) to propose new test cases, output formats, or integrations.

Open a feature request: [github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=feature_request.md](https://github.com/OWASP/www-project-api-security-testing-framework/issues/new?template=feature_request.md)

### Test Case Enhancements

If a specific vulnerability detection is missing or producing false positives, use the [Test Case Enhancement template](.github/ISSUE_TEMPLATE/test_case_enhancement.md).

### Documentation Improvements

Use the [Documentation Improvement template](.github/ISSUE_TEMPLATE/documentation_improvement.md) for anything unclear or missing in these docs.
