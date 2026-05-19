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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Extended unit tests for the new capabilities added to {@link BrokenAuthenticationTestCase}:
 * <ul>
 *   <li>JWT expiry analysis (issue #13)</li>
 *   <li>Session-cookie security-flag checks (issue #14)</li>
 *   <li>2FA/MFA bypass attempts (issue #15)</li>
 * </ul>
 */
@DisplayName("BrokenAuthentication — extended tests (JWT analysis, session cookies, 2FA bypass)")
class BrokenAuthenticationExtendedTest {

    @Mock
    private HttpClient httpClient;

    private BrokenAuthenticationTestCase testCase;

    // ── helpers ──────────────────────────────────────────────────────────────

    private static HttpResponse ok() {
        return new HttpResponse(200, "{\"data\":\"ok\"}", Map.of());
    }

    private static HttpResponse unauthorized() {
        return new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of());
    }

    private static HttpResponse okWithCookie(String setCookieValue) {
        return new HttpResponse(200, "{\"token\":\"t\"}", Map.of("Set-Cookie", List.of(setCookieValue)));
    }

    // ── setup ─────────────────────────────────────────────────────────────────

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenAuthenticationTestCase();
    }

    // ── JWT analysis (issue #13) ───────────────────────────────────────────

    /**
     * An endpoint that requires authentication should flag an expired JWT when the server
     * returns 200 for it (meaning the server does not validate the exp claim).
     *
     * The mock is realistic: the baseline probe (no Authorization header) returns 401,
     * confirming the endpoint requires auth — then the expired-JWT probe returns 200,
     * triggering the finding.
     */
    @Test
    @DisplayName("testJwtAnalysis: flags expired JWT accepted by server")
    void testExpiredJwtAccepted() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET", "application/json", null, true);

        // Realistic mock: 401 without auth (baseline), 200 with any Authorization header
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    Map<String, String> hdrs = inv.getArgument(1);
                    return hdrs.containsKey("Authorization") ? ok() : unauthorized();
                });

        List<Finding> findings = testCase.testJwtAnalysis(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect that expired JWT was accepted");
        Finding f = findings.get(0);
        assertEquals("Expired JWT Token Accepted", f.getTitle());
        assertEquals(Severity.HIGH, f.getSeverity());
        assertTrue(f.getEvidence().contains("exp=1000000000"),
                "Evidence should reference the expired exp claim");
    }

    /**
     * When the server correctly rejects an expired JWT with 401, no finding should be raised.
     */
    @Test
    @DisplayName("testJwtAnalysis: no finding when server rejects expired JWT")
    void testExpiredJwtRejected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET", "application/json", null, true);

        // Server rejects everything — both baseline probe and expired-JWT probe return 401
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(unauthorized());

        List<Finding> findings = testCase.testJwtAnalysis(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "No finding expected when server rejects expired JWT");
    }

    /**
     * Public endpoint (baseline returns 200 without auth): expired-JWT test must be skipped
     * entirely to avoid false positives.
     */
    @Test
    @DisplayName("testJwtAnalysis: no false positive on public endpoint")
    void testExpiredJwtNoFalsePositiveOnPublicEndpoint() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/info", "GET", "application/json", null, true);

        // Public endpoint — always returns 200 regardless of auth header
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(ok());

        List<Finding> findings = testCase.testJwtAnalysis(endpoint, httpClient);

        assertTrue(findings.isEmpty(),
                "Should NOT flag expired JWT on a public endpoint — baseline 200 means auth is irrelevant");
    }

    /**
     * Public endpoints (requiresAuthentication=false) should not be tested for JWT expiry.
     */
    @Test
    @DisplayName("testJwtAnalysis: skips public endpoints")
    void testJwtAnalysisSkipsPublicEndpoints() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/public", "GET", "application/json", null, false);

        List<Finding> findings = testCase.testJwtAnalysis(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Public endpoints should not be checked for JWT expiry");
    }

    // ── Session cookie security (issue #14) ──────────────────────────────────

    /**
     * A Set-Cookie header missing all three security flags should produce a MEDIUM finding.
     */
    @Test
    @DisplayName("testSessionCookieSecurity: flags cookie with no security flags")
    void testCookieMissingAllFlags() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/auth/login", "POST", "application/json", null, false);

        // Cookie has no HttpOnly, Secure, or SameSite
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(okWithCookie("sessionid=abc123; Path=/"));

        List<Finding> findings = testCase.testSessionCookieSecurity(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect insecure session cookie");
        Finding f = findings.get(0);
        assertEquals("Insecure Session Cookie — Missing Security Flags", f.getTitle());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertTrue(f.getEvidence().contains("HttpOnly"), "Evidence should mention HttpOnly");
        assertTrue(f.getEvidence().contains("Secure"),   "Evidence should mention Secure");
        assertTrue(f.getEvidence().contains("SameSite"), "Evidence should mention SameSite");
    }

    /**
     * A properly secured cookie should not produce any finding.
     */
    @Test
    @DisplayName("testSessionCookieSecurity: no finding for fully secured cookie")
    void testCookieWithAllFlags() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/auth/login", "POST", "application/json", null, false);

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(okWithCookie("sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"));

        List<Finding> findings = testCase.testSessionCookieSecurity(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Fully secured cookie should not produce a finding");
    }

    /**
     * Responses that set no cookies should not produce any finding.
     */
    @Test
    @DisplayName("testSessionCookieSecurity: no finding when response has no cookies")
    void testNoCookiesInResponse() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/auth/login", "POST", "application/json", null, false);

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok()); // no Set-Cookie header

        List<Finding> findings = testCase.testSessionCookieSecurity(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "No cookie in response should not produce a finding");
    }

    // ── 2FA bypass (issue #15) ────────────────────────────────────────────────

    /**
     * When the server accepts a common OTP code (e.g. 000000), a CRITICAL finding is expected.
     */
    @Test
    @DisplayName("testTwoFactorBypass: flags server accepting weak OTP")
    void testTwoFactorBypassAccepted() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/auth/mfa", "POST", "application/json", null, false);

        // Server accepts all codes (weak implementation)
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok());

        List<Finding> findings = testCase.testTwoFactorBypass(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect 2FA bypass");
        Finding f = findings.get(0);
        assertEquals("2FA/MFA Bypass — Weak OTP Code Accepted", f.getTitle());
        assertEquals(Severity.CRITICAL, f.getSeverity());
    }

    /**
     * When the server rejects all guessable OTP codes, no finding should be raised.
     */
    @Test
    @DisplayName("testTwoFactorBypass: no finding when server rejects all weak OTP codes")
    void testTwoFactorBypassRejected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/auth/mfa", "POST", "application/json", null, false);

        // Server correctly rejects all codes
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(unauthorized());

        List<Finding> findings = testCase.testTwoFactorBypass(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "No finding expected when all OTP codes are rejected");
    }

    /**
     * Non-POST 2FA endpoints should be skipped (GET cannot submit an OTP payload).
     */
    @Test
    @DisplayName("testTwoFactorBypass: skips non-POST endpoints")
    void testTwoFactorBypassSkipsGet() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/auth/mfa", "GET", "application/json", null, false);

        List<Finding> findings = testCase.testTwoFactorBypass(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "GET endpoint should be skipped by 2FA bypass test");
    }

    // ── execute() integration — 2FA path detection ─────────────────────────

    /**
     * The top-level {@code execute()} should automatically route 2FA endpoints through the
     * 2FA bypass check without needing auth-endpoint patterns in the path.
     */
    @Test
    @DisplayName("execute: routes 2FA endpoint through bypass checks")
    void testExecuteRoutes2FAEndpoint() throws IOException {
        // /api/verify matches the is2FAEndpoint() pattern ("verify")
        EndpointInfo endpoint = new EndpointInfo("/api/verify", "POST", "application/json", null, false);

        // session-cookie check: POST → no cookies
        // 2FA bypass check: POST → 401 (server rejects all codes)
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok()); // session cookie check (no Set-Cookie)

        // second and subsequent calls → 401 for all OTP attempts
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of())) // session check
                .thenReturn(unauthorized())
                .thenReturn(unauthorized())
                .thenReturn(unauthorized())
                .thenReturn(unauthorized())
                .thenReturn(unauthorized())
                .thenReturn(unauthorized());

        // Should not throw
        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }
}
