package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Set;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("SqlNoSqlInjectionTestCase unit tests")
class SqlNoSqlInjectionTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private SqlNoSqlInjectionTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new SqlNoSqlInjectionTestCase();
    }

    @Test
    @DisplayName("getId / getName / getDescription return expected values")
    void testMetadata() {
        assertEquals("ASTF-INJECTION-2023", testCase.getId());
        assertEquals("SQL/NoSQL Injection", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Skips GET endpoints with no path parameter — nothing to inject into")
    void testSkipsGetEndpointsWithoutPathParameter() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/search", "GET");
        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects SQL injection via an unresolved path parameter on a GET endpoint (regression, VAmPI live-test gap)")
    void testDetectsSqlInjectionViaPathParameter() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/{username}", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(500, "sqlite3::OperationalError near \"'\"", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect SQL injection via the path parameter");
        assertEquals("SQL Injection Vulnerability", findings.get(0).getTitle());
        assertTrue(findings.get(0).getRequestDetails().contains("GET"));
    }

    @Test
    @DisplayName("Detects SQL injection via an ALREADY-RESOLVED path segment (Scanner resolves templates before test cases run)")
    void testDetectsSqlInjectionViaResolvedPathSegment() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/name1", "GET");
        endpoint.setBaseUrl("https://example.com");
        endpoint.setResolvedFromTemplate(true);

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(500, "sqlite3::OperationalError near \"'\"", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect SQL injection via the resolved path segment");
        assertEquals("SQL Injection Vulnerability", findings.get(0).getTitle());
    }

    @Test
    @DisplayName("Does not flag path-parameter SQL injection when the response is clean")
    void testNoSqlInjectionViaPathParameterWhenClean() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/{username}", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{\"error\":\"user not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects SQL injection when a database error is reflected, independent of path naming")
    void testDetectsSqlInjectionViaErrorMessage() throws IOException {
        // Deliberately NOT a webhook/proxy/sync path — the exact gap #96 was filed for.
        EndpointInfo endpoint = new EndpointInfo("/api/users/search", "POST", "application/json",
                "{\"query\":\"alice\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(500,
                        "{\"error\":\"You have an error in your SQL syntax near '''"+"\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect SQL injection from the reflected DB error");
        assertEquals("SQL Injection Vulnerability", findings.get(0).getTitle());
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Detects SQL injection via a real Python/SQLAlchemy error page (regression: VAmPI live-test gap)")
    void testDetectsSqlInjectionViaSqlAlchemyError() throws IOException {
        // The exact error shape VAmPI's real SQLi vulnerability produces — confirmed missing
        // entirely from SQL_ERROR_INDICATORS until found via live testing.
        EndpointInfo endpoint = new EndpointInfo("/users/v1/name1", "GET");
        endpoint.setBaseUrl("https://example.com");
        endpoint.setResolvedFromTemplate(true);

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(500,
                        "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token: \"'''\"",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect SQL injection from a real SQLAlchemy/sqlite3 error");
        assertEquals("SQL Injection Vulnerability", findings.get(0).getTitle());
    }

    @Test
    @DisplayName("Does not flag SQL injection when no error indicator is present")
    void testNoSqlInjectionWhenClean() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/search", "POST", "application/json",
                "{\"query\":\"alice\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"results\":[]}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects NoSQL authentication bypass when a MongoDB operator replaces the password field")
    void testDetectsNoSqlAuthBypass() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/login", "POST", "application/json",
                "{\"username\":\"alice\",\"password\":\"secret\"}", false);
        endpoint.setBaseUrl("https://example.com");

        // Fallback for every other field/payload combination (username field, other payload
        // shapes on password, etc.) — defined first so the more specific stubs below take
        // precedence over it.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400, "{\"error\":\"invalid credentials\"}", Map.of()));
        // The password field, specifically, accepts a MongoDB operator and succeeds.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"password\":{\"$ne\": null}"))))
                .thenReturn(new HttpResponse(200, "{\"token\":\"abc123\",\"message\":\"Login successful\"}", Map.of()));
        // Baseline (obviously-invalid password value) must fail for the bypass check to fire.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"password\":\"astf-nosql-baseline-value\""))))
                .thenReturn(new HttpResponse(401, "{\"error\":\"invalid credentials\"}", Map.of()));

        // The target answers the same without credentials as with them.
        OpenTargetStubs.answerNoAuthLikeCredentialed(httpClient);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect NoSQL auth bypass");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Authentication Bypass")));
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Does not flag NoSQL bypass when the operator payload is correctly rejected")
    void testNoNoSqlBypassWhenRejected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/login", "POST", "application/json",
                "{\"username\":\"alice\",\"password\":\"secret\"}", false);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400, "{\"error\":\"invalid credentials\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects a NoSQL/logic bypass on a non-credential, non-auth-path field " +
            "(regression: crAPI's coupon-code field, TRACEABILITY.md row 12)")
    void testDetectsNoSqlBypassOnCouponField() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/workshop/api/shop/apply_coupon", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        // Fallback: everything else (other field, other payload shapes) is rejected.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Coupon not found\"}", Map.of()));
        // A string-shaped operator payload on coupon_code (survives a CharField/type check) succeeds.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"coupon_code\":\"$ne\""))))
                .thenReturn(new HttpResponse(200, "{\"message\":\"Coupon applied successfully\"}", Map.of()));
        // Baseline (obviously-invalid coupon code) fails.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null &&
                        body.contains("\"coupon_code\":\"astf-nosql-baseline-value\""))))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Coupon not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect the generalized NoSQL/logic bypass on the coupon field");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Authorization/Logic Bypass")));
    }

    @Test
    @DisplayName("Preserves a numeric sibling field's real type instead of forcing it to a string " +
            "(regression: a strict 'amount' integer validator would reject every request otherwise, " +
            "masking any injection on the field actually under test)")
    void testPreservesSiblingFieldOriginalType() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/workshop/api/shop/apply_coupon", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Coupon not found\"}", Map.of()));

        testCase.execute(endpoint, httpClient);

        verify(httpClient, atLeastOnce()).postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"amount\":10")));
        verify(httpClient, never()).postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"amount\":\"test\"")));
    }

    @Test
    @DisplayName("Detects a bypass even when an unrelated field's value contains a generic failure word " +
            "(regression: scanning the whole body for words like 'invalid' previously risked masking a " +
            "real bypass whenever unrelated response content happened to contain one)")
    void testBypassNotMaskedByUnrelatedFailureWordInBody() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/workshop/api/shop/apply_coupon", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Coupon not found\"}", Map.of()));
        // Success response's "message" field is clean, but an unrelated field happens to contain "invalid".
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"coupon_code\":\"$ne\""))))
                .thenReturn(new HttpResponse(200, "{\"message\":\"Coupon applied successfully\"," +
                        "\"related_note\":\"invalid coupons expire after 30 days\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null &&
                        body.contains("\"coupon_code\":\"astf-nosql-baseline-value\""))))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Coupon not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(),
                "Unrelated 'invalid' text elsewhere in the body should not mask a real bypass");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Authorization/Logic Bypass")));
    }

    @Test
    @DisplayName("Extracts message-field text from an array-rooted response body too " +
            "(regression: a top-level JSON array, e.g. a batch-style response, previously fell back " +
            "to the old whole-body scan since message-field extraction bailed out before recursing " +
            "into it)")
    void testBypassNotMaskedByUnrelatedFailureWordInArrayRootedBody() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/workshop/api/shop/apply_coupon", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        // Baseline rejection is only signaled via a "message" field nested inside a top-level array.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "[{\"message\":\"Coupon not found\"}]", Map.of()));
        // Success response's "message" field is clean, but an unrelated field happens to contain "invalid".
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"coupon_code\":\"$ne\""))))
                .thenReturn(new HttpResponse(200, "[{\"message\":\"Coupon applied successfully\"," +
                        "\"related_note\":\"invalid coupons expire after 30 days\"}]", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null &&
                        body.contains("\"coupon_code\":\"astf-nosql-baseline-value\""))))
                .thenReturn(new HttpResponse(200, "[{\"message\":\"Coupon not found\"}]", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(),
                "Should still detect the bypass when the response body is array-rooted");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Authorization/Logic Bypass")));
    }

    @Test
    @DisplayName("Sends the NoSQL baseline request at most once per field, even when every payload " +
            "succeeds for that field (regression: avoids multiplying live/side-effecting requests " +
            "against the target for every payload that happens to succeed)")
    void testNoSqlBaselineRequestCachedPerField() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/search", "POST", "application/json",
                "{\"query\":\"alice\"}", true);
        endpoint.setBaseUrl("https://example.com");

        // Every operator payload on "query" succeeds without a failure marker, and so does the
        // baseline — so nothing short-circuits the loop, and every payload for the field gets
        // tried. Without caching, that would mean one baseline call per payload.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"results\":[]}", Map.of()));

        testCase.execute(endpoint, httpClient);

        verify(httpClient, times(1)).postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("astf-nosql-baseline-value")));
    }

    @Test
    @DisplayName("Detects SQL injection behaviorally when a 500 appears with no DB-error text in the body " +
            "(regression: crAPI's apply_coupon, whose own exception handler crashes into a content-free page)")
    void testDetectsSqlInjectionBehaviorallyWhenNoErrorTextLeaks() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/workshop/api/shop/apply_coupon", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        // Clean/baseline values succeed; a bare single quote produces a content-free 500.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("'"))))
                .thenReturn(new HttpResponse(500, "<html><body>Server Error (500)</body></html>", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && !body.contains("'"))))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Coupon not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect SQL injection via the behavioral 500-vs-baseline signal");
        assertEquals("Possible SQL Injection (Behavioral)", findings.get(0).getTitle());
        assertEquals(Severity.MEDIUM, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Does not flag behavioral SQL injection when the baseline itself already errors")
    void testNoBehavioralSqlInjectionWhenBaselineAlsoErrors() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/broken", "POST", "application/json",
                "{\"field\":\"value\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(500, "<html>always broken</html>", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "A 500 baseline can't attribute the later 500 to the injected payload");
    }

    @Test
    @DisplayName("Does not flag behavioral SQL injection when both baseline and payload succeed")
    void testNoBehavioralSqlInjectionWhenBothSucceed() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fine", "POST", "application/json",
                "{\"field\":\"value\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"ok\":true}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Uses common field names when the endpoint has no discovered request body")
    void testFallsBackToCommonFieldNamesWhenNoBody() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/comments", "POST", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }

    @Test
    @DisplayName("Handles exceptions gracefully without propagating them")
    void testHandlesExceptionsGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/search", "POST", "application/json",
                "{\"query\":\"alice\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Keeps testing remaining fields after a confirmed NoSQL bypass on one field " +
            "(regression: an early return previously stopped at the first vulnerable field)")
    void testNoSqlBypassReportedForEveryVulnerableField() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/redeem", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\",\"voucher\":\"GIFT5\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Code not found\"}", Map.of()));
        // Both fields independently accept a string-shaped operator payload.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && (body.contains("\"coupon_code\":\"$ne\"") ||
                        body.contains("\"voucher\":\"$ne\"")))))
                .thenReturn(new HttpResponse(200, "{\"message\":\"Applied\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertEquals(2, findings.size(), "Each vulnerable field should produce its own finding");
        assertTrue(findings.stream().anyMatch(f -> f.getRequestDetails().contains("Field: coupon_code")));
        assertTrue(findings.stream().anyMatch(f -> f.getRequestDetails().contains("Field: voucher")));
    }

    // ── reproducibility and transient re-check errors (follow-up to #142) ───

    @Test
    @DisplayName("A one-off success that turns into 'already exists' is reported only as a MEDIUM possible " +
            "bypass, never CRITICAL (VAmPI /users/v1/register)")
    void testOneOffStateChangeIsNotCritical() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/register", "POST", "application/json",
                "{\"username\":\"alice\",\"email\":\"alice@example.com\"}", false);
        endpoint.setBaseUrl("https://example.com");

        // Each distinct body creates its user the first time and fails with "already exists" after that.
        Set<String> seen = new HashSet<>();
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            String body = inv.getArgument(3);
            if (body.contains("astf-nosql-baseline-value") || !seen.add(body)) {
                return new HttpResponse(200, "{ \"status\": \"fail\", \"message\": \"User already exists.\" }", Map.of());
            }
            return new HttpResponse(200, "{\"message\":\"Successfully registered. Login to receive an auth token.\"}", Map.of());
        });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getSeverity() == Severity.CRITICAL),
                "a one-off state change must never be reported as a CRITICAL bypass");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Possible Bypass (not reproducible)")
                && f.getSeverity() == Severity.MEDIUM), "it is still reported, at MEDIUM, so nothing is dropped");
    }

    @Test
    @DisplayName("A bypass that succeeds again when the payload is re-sent is reported as CRITICAL")
    void testReproducibleBypassIsCritical() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/redeem", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv ->
                ((String) inv.getArgument(3)).contains("\"coupon_code\":\"$ne\"")
                        ? new HttpResponse(200, "{\"credit\":75}", Map.of())
                        : new HttpResponse(400, "{\"message\":\"Code not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertEquals(1, findings.size());
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getTitle().contains("Authorization/Logic Bypass"));
    }

    @Test
    @DisplayName("A transient error on the baseline re-check keeps the finding instead of dropping it")
    void testTransientBaselineRecheckErrorKeepsFinding() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/redeem", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\"}", true);
        endpoint.setBaseUrl("https://example.com");

        AtomicInteger baselines = new AtomicInteger();
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            String body = inv.getArgument(3);
            if (body.contains("astf-nosql-baseline-value")) {
                if (baselines.incrementAndGet() == 2) {
                    throw new IOException("Connection reset");   // the re-check fails once
                }
                return new HttpResponse(400, "{\"message\":\"Code not found\"}", Map.of());
            }
            return body.contains("\"coupon_code\":\"$ne\"")
                    ? new HttpResponse(200, "{\"credit\":75}", Map.of())
                    : new HttpResponse(400, "{\"message\":\"Code not found\"}", Map.of());
        });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertEquals(1, findings.size(), "a real bypass must not be dropped because one re-check request failed");
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("A NoSQL error disclosure on one field does not mask a bypass on a sibling field")
    void testNoSqlErrorOnOneFieldDoesNotMaskBypassOnAnother() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/redeem", "POST", "application/json",
                "{\"query\":\"alice\",\"coupon_code\":\"WELCOME10\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400, "{\"message\":\"Code not found\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"query\":{\"$ne\": null}"))))
                .thenReturn(new HttpResponse(500, "{\"message\":\"MongoError: bad query\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"coupon_code\":\"$ne\""))))
                .thenReturn(new HttpResponse(200, "{\"message\":\"Applied\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Database Error Disclosed")));
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Authorization/Logic Bypass")
                && f.getSeverity() == Severity.CRITICAL));
    }

    @Test
    @DisplayName("Recognises a failure reported via a non-standard message field (e.g. errorMsg) " +
            "by falling back to a whole-body scan (regression: valid JSON with no recognised " +
            "message field previously got no text-marker coverage at all)")
    void testFailureInNonStandardMessageFieldDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/workshop/api/shop/apply_coupon", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        // Every response is HTTP 200; the only failure signal is an "errorMsg" field.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"errorMsg\":\"Coupon invalid\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"coupon_code\":\"$ne\""))))
                .thenReturn(new HttpResponse(200, "{\"applied\":true}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Authorization/Logic Bypass")),
                "The errorMsg baseline should be read as a failure, confirming the bypass");
        // Payloads whose own response carries the errorMsg failure must not be reported.
        assertTrue(findings.stream().allMatch(f -> f.getRequestDetails().contains("Payload: \"$ne\"")));
    }

    @Test
    @DisplayName("Does not flag a bypass on a permissive endpoint that echoes the submitted value back " +
            "(regression guard: the baseline sentinel must not itself contain a failure-marker word, or " +
            "the whole-body fallback would read our own echoed sentinel as a failed baseline)")
    void testNoNoSqlBypassWhenEndpointEchoesInput() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/notes", "POST", "application/json",
                "{\"title\":\"hello\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        // Accepts anything and echoes the request body back — no message field, no failure signal.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> new HttpResponse(200, inv.getArgument(3), Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "An endpoint that accepts every value has no bypass to report");
    }

    // ── #142: false CRITICAL findings when the target degrades mid-scan ───────────────────────

    private static boolean isBaselineRequest(Object body) {
        return body != null && body.toString().contains("astf-nosql-baseline-value");
    }

    @Test
    @DisplayName("Does not flag a bypass when a degraded target answers 200 with a pretty-printed " +
            "\"status\": \"fail\" (regression, #142: VAmPI /users/v1/login)")
    void testNoNoSqlBypassWhenFailureIsPrettyPrintedStatusFail() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/login", "POST", "application/json",
                "{\"username\":\"name1\",\"password\":\"pass1\"}", false);
        endpoint.setBaseUrl("https://example.com");

        // Healthy baseline: a recognised failure. Everything else, payloads included, is the
        // degraded answer VAmPI gave once a ReDoS probe had wedged it. Note the spaces after the
        // colons, which a literal "status":"fail" substring never matched.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> isBaselineRequest(inv.getArgument(3))
                        ? new HttpResponse(200, "{ \"status\": \"fail\", \"message\": \"Username does not exist\" }", Map.of())
                        : new HttpResponse(200, "{ \"status\": \"fail\", \"message\": \"An error occurred!\" }", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Bypass")),
                "A response that says status: fail is a failure however it is formatted");
    }

    @Test
    @DisplayName("Does not flag a bypass when the cached baseline went stale: a fresh baseline no longer fails " +
            "(regression, #142: baseline taken while healthy, payloads answered while degraded)")
    void testNoNoSqlBypassWhenFreshBaselineNoLongerFails() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders", "POST", "application/json",
                "{\"note\":\"hello\",\"amount\":10}", true);
        endpoint.setBaseUrl("https://example.com");

        java.util.concurrent.atomic.AtomicInteger baselineCalls = new java.util.concurrent.atomic.AtomicInteger();
        // The first baseline is taken while the target is healthy and fails. From then on the
        // target answers everything, an invalid value included, with the same unrecognised 200.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    if (isBaselineRequest(inv.getArgument(3)) && baselineCalls.getAndIncrement() == 0) {
                        return new HttpResponse(400, "{\"detail\":\"rejected\"}", Map.of());
                    }
                    return new HttpResponse(200, "{\"result\":\"done\"}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Bypass")),
                "A baseline that no longer fails means the target's behaviour changed: inconclusive, not a bypass");
        assertTrue(baselineCalls.get() >= 2, "The baseline must have been re-sent before anything was reported");
    }

    @Test
    @DisplayName("Still reports a real bypass when the fresh baseline also fails")
    void testStillReportsBypassWhenFreshBaselineStillFails() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/shop/apply", "POST", "application/json",
                "{\"code\":\"SAVE10\"}", true);
        endpoint.setBaseUrl("https://example.com");

        java.util.concurrent.atomic.AtomicInteger baselineCalls = new java.util.concurrent.atomic.AtomicInteger();
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    if (isBaselineRequest(inv.getArgument(3))) {
                        baselineCalls.incrementAndGet();
                        return new HttpResponse(400, "{\"error\":\"coupon rejected\"}", Map.of());
                    }
                    return new HttpResponse(200, "{\"applied\":true,\"discount\":10}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Bypass")),
                "A target that stays healthy and still accepts the operator must keep being reported");
        assertEquals(2, baselineCalls.get(),
                "One cached baseline plus exactly one fresh re-send for the single reported finding");
    }

    @Test
    @DisplayName("A top-level error field marks a 200 response as a failure")
    void testTopLevelErrorFieldIsAFailure() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/shop/apply", "POST", "application/json",
                "{\"code\":\"SAVE10\"}", true);
        endpoint.setBaseUrl("https://example.com");

        // "bad coupon code" matches none of the text markers: only the error field says it failed.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> isBaselineRequest(inv.getArgument(3))
                        ? new HttpResponse(400, "{\"error\":\"bad coupon code\"}", Map.of())
                        : new HttpResponse(200, "{\"error\":\"bad coupon code\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Bypass")));
    }

    @Test
    @DisplayName("An empty or null error field is not a failure, so a real bypass is still reported")
    void testEmptyErrorFieldIsNotAFailure() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/shop/apply", "POST", "application/json",
                "{\"code\":\"SAVE10\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> isBaselineRequest(inv.getArgument(3))
                        ? new HttpResponse(400, "{\"error\":\"coupon rejected\"}", Map.of())
                        : new HttpResponse(200, "{\"errors\":[],\"error\":null,\"applied\":true}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Bypass")),
                "errors: [] and error: null mean no error, so the success must not be discarded");
    }

    @Test
    @DisplayName("When a fresh baseline no longer fails, the result is reported as INFO inconclusive, not dropped")
    void testChangedBaselineIsReportedAsInconclusive() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/redeem", "POST", "application/json",
                "{\"coupon_code\":\"WELCOME10\"}", true);
        endpoint.setBaseUrl("https://example.com");

        AtomicInteger baselines = new AtomicInteger();
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            String body = inv.getArgument(3);
            if (body.contains("astf-nosql-baseline-value")) {
                return baselines.incrementAndGet() == 1
                        ? new HttpResponse(400, "{\"message\":\"Code not found\"}", Map.of())
                        : new HttpResponse(200, "{\"credit\":75}", Map.of());   // behaviour changed
            }
            return body.contains("\"coupon_code\":\"$ne\"")
                    ? new HttpResponse(200, "{\"credit\":75}", Map.of())
                    : new HttpResponse(400, "{\"message\":\"Code not found\"}", Map.of());
        });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertEquals(1, findings.size());
        assertEquals(Severity.INFO, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getTitle().contains("Inconclusive"));
    }

    @Test
    @DisplayName("A baseline that answers with a server error cannot establish a bypass: INFO inconclusive, never CRITICAL")
    void testServerErrorBaselineIsInconclusive() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/register", "POST", "application/json",
                "{\"username\":\"alice\",\"id\":\"1\"}", false);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            String body = inv.getArgument(3);
            if (body.contains("astf-nosql-baseline-value")) {
                return new HttpResponse(500, "<html>Internal Server Error</html>", Map.of());
            }
            return body.contains("$") || body.contains("return true")
                    ? new HttpResponse(200, "{\"message\":\"ok\"}", Map.of())
                    : new HttpResponse(400, "{\"message\":\"bad\"}", Map.of());
        });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.MEDIUM
                && f.getTitle().contains("NoSQL")), "a 5xx baseline must not produce a bypass finding");
        assertTrue(findings.stream().anyMatch(f -> f.getSeverity() == Severity.INFO
                && f.getTitle().contains("server error")), "it is still reported, as INFO");
    }
}
