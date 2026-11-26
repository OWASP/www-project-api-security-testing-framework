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

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UnsafeConsumptionOfApisTestCase} (OWASP API10:2023).
 *
 * <p>Key behavioural notes from the implementation:
 * <ul>
 *   <li>{@code testInjectionViaIntegrationEndpoints} only runs on paths containing integration
 *       patterns (webhook, proxy, integration, external, callback, third-party, import, export …).
 *       The pattern "49" is explicitly excluded from injection detection to avoid false positives.</li>
 *   <li>{@code testOpenRedirect} only runs on GET endpoints and checks that the {@code Location}
 *       response header echoes the attacker domain.</li>
 *   <li>{@code checkTlsForExternalCalls} only runs on integration endpoints with POST or PUT,
 *       and reports a finding when the server returns 200/201 for an HTTP callback URL.</li>
 * </ul>
 */
@DisplayName("Unsafe Consumption of APIs Test Case Tests")
class UnsafeConsumptionOfApisTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private UnsafeConsumptionOfApisTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new UnsafeConsumptionOfApisTestCase();
    }

    // -------------------------------------------------------------------------
    // Helper factories
    // -------------------------------------------------------------------------

    private static HttpResponse ok() {
        return new HttpResponse(200, "{\"data\":\"ok\"}", Map.of());
    }

    private static HttpResponse notFound() {
        return new HttpResponse(404, "{}", Map.of());
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should have correct ID and name")
    void testMetadata() {
        assertEquals("ASTF-API10-2023", testCase.getId());
        assertEquals("Unsafe Consumption of APIs", testCase.getName());
    }

    @Test
    @DisplayName("Should detect injection when webhook endpoint reflects unescaped script tag")
    void testInjectionDetectedOnWebhookEndpoint() throws IOException {
        // /api/webhook contains "webhook" — an integration path pattern
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "POST");

        // Response body contains an unescaped <script> tag — detected as injection
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"data\":\"<script>alert('xss')</script>\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report a finding when injection is reflected");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("Injection")),
                "Finding title should reference injection");
    }

    @Test
    @DisplayName("Should NOT report injection finding for non-integration endpoint path")
    void testNoInjectionFindingOnNonIntegrationEndpoint() throws IOException {
        // /api/users does NOT contain any integration path pattern
        EndpointInfo endpoint = new EndpointInfo("/api/users", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"data\":\"<script>alert('xss')</script>\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Injection")),
                "Should NOT report injection for non-integration endpoints");
    }

    @Test
    @DisplayName("Should detect SQL injection when a 500 response contains a database error (regression)")
    void testSqlInjectionDetectedOn500() throws IOException {
        // Error-based SQL injection almost always surfaces as a 500 with the raw DB error,
        // not a 2xx — this must be detected even though the response is a server error.
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(500,
                        "{\"error\":\"You have an error in your SQL syntax; check the manual that " +
                        "corresponds to your MySQL server version\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("SQL Injection")),
                "Should detect SQL injection from a 500 response containing a database error");
    }

    @Test
    @DisplayName("Should detect open redirect when Location header echoes attacker domain")
    void testOpenRedirectDetected() throws IOException {
        // GET endpoint — testOpenRedirect only fires on GET
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // 302 response with Location pointing to attacker domain
        HttpResponse redirectResponse = new HttpResponse(
                302,
                "",
                Map.of("Location", List.of("https://evil-attacker.example.com/phishing"))
        );

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(redirectResponse);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report a finding when open redirect is detected");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("Redirect")),
                "Finding title should reference open redirect");
    }

    @Test
    @DisplayName("Open redirect evidence masks token-like query values in the Location header")
    void testOpenRedirectEvidenceMasksTokens() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        HttpResponse redirectResponse = new HttpResponse(302, "",
                Map.of("Location", List.of("https://evil-attacker.example.com/cb?access_token=s3cr3tvalue&next=/home")));
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(redirectResponse);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        Finding f = findings.stream().filter(x -> x.getTitle().contains("Redirect")).findFirst().orElseThrow();
        assertFalse(f.getEvidence().contains("s3cr3tvalue"), "Token value must not appear in evidence");
        assertTrue(f.getEvidence().contains("evil-attacker.example.com"), "Redirect target should stay");
        assertTrue(f.getEvidence().contains("next=/home"), "Non-token parameters should stay");
    }

    @Test
    @DisplayName("Should NOT report open redirect when server returns 200 with no attacker Location header")
    void testNoOpenRedirectWhenLocationIsSafe() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // Server returns 200 — not a redirect, so no open-redirect finding
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(ok());

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Redirect")),
                "Should NOT report open redirect when response is not a redirect");
    }

    @Test
    @DisplayName("Should report MEDIUM TLS finding when integration endpoint accepts HTTP callback URL")
    void testTlsCheckFlagsHttpCallback() throws IOException {
        // /api/webhook is an integration endpoint. POST method triggers both injection and TLS checks.
        // We return a clean body (no injection indicators) so only the TLS finding is produced.
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "POST");

        // Body contains no injection-success pattern keywords — only 200 status for TLS check to fire
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"accepted\":true}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report a finding when HTTP callback URL is accepted");
        assertTrue(
                findings.stream().anyMatch(f ->
                        f.getTitle().contains("Insecure") || f.getTitle().contains("TLS")
                                || f.getTitle().contains("Webhook") || f.getTitle().contains("HTTP")),
                "Finding title should reference insecure HTTP webhook/callback");
    }

    @Test
    @DisplayName("Should handle IOException gracefully and not propagate the exception")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        assertNotNull(findings);
    }

    private static final String STRIPE_BODY =
            "{\"id\":\"evt_astf_test\",\"type\":\"ping\",\"data\":{\"object\":{}}}";
    private static final String GITHUB_BODY = "{\"zen\":\"astf-ping\",\"hook_id\":1}";

    private static List<Finding> signatureFindings(List<Finding> findings) {
        return findings.stream()
                .filter(f -> f.getTitle().startsWith("Webhook Accepts") || f.getTitle().startsWith("Webhook Signature"))
                .toList();
    }

    @Test
    @DisplayName("Stripe webhook accepting an unsigned event and saying received is CRITICAL")
    void testStripeUnsignedAcceptedIsCritical() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/stripe/webhook", "POST");
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            Map<String, String> headers = inv.getArgument(1);
            String body = inv.getArgument(3);
            if (STRIPE_BODY.equals(body) && headers.isEmpty()) {
                return new HttpResponse(200, "{\"received\":true}", Map.of());
            }
            return new HttpResponse(400, "{\"error\":\"bad\"}", Map.of());
        });

        List<Finding> findings = signatureFindings(testCase.execute(endpoint, httpClient));

        assertEquals(1, findings.size());
        assertEquals("Webhook Accepts Unsigned/Forged Events", findings.get(0).getTitle());
        assertEquals(org.owasp.astf.core.result.Severity.CRITICAL, findings.get(0).getSeverity());
        verify(httpClient, never()).postWithStatus(anyString(), argThat(h -> h.containsKey("X-Hub-Signature-256")),
                anyString(), anyString());
    }

    @Test
    @DisplayName("GitHub webhook accepting a wrong signature and processing the event is CRITICAL")
    void testGithubWrongSignatureAcceptedIsCritical() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/hooks/github", "POST");
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            Map<String, String> headers = inv.getArgument(1);
            String body = inv.getArgument(3);
            if (GITHUB_BODY.equals(body) && headers.getOrDefault("X-Hub-Signature-256", "").startsWith("sha256=0")) {
                return new HttpResponse(200, "{\"status\":\"queued\",\"zen\":\"astf-ping\"}", Map.of());
            }
            return new HttpResponse(401, "", Map.of());
        });

        List<Finding> findings = signatureFindings(testCase.execute(endpoint, httpClient));

        assertEquals(1, findings.size());
        assertEquals("Webhook Accepts Unsigned/Forged Events", findings.get(0).getTitle());
        assertTrue(findings.get(0).getEvidence().contains("invalid signature"));
    }

    @Test
    @DisplayName("Webhook returning 200 with an empty body is reported as MEDIUM, not confirmed")
    void testEmptyBodyAcceptedIsMedium() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/webhook/slack", "POST");
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "", Map.of()));

        List<Finding> findings = signatureFindings(testCase.execute(endpoint, httpClient));

        assertEquals(1, findings.size());
        assertEquals("Webhook Signature Check Not Confirmed", findings.get(0).getTitle());
        assertEquals(org.owasp.astf.core.result.Severity.MEDIUM, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Webhook rejecting every variant with 401 produces no signature finding")
    void testAllVariantsRejectedNoFinding() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/webhooks/payments", "POST");
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"invalid signature\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(signatureFindings(findings).isEmpty());
        verify(httpClient, atLeastOnce()).postWithStatus(anyString(), anyMap(), anyString(), eq(STRIPE_BODY));
    }

    @Test
    @DisplayName("Non-webhook path does not run the signature check")
    void testNonWebhookPathSendsNothing() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "POST");

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(signatureFindings(findings).isEmpty());
        verify(httpClient, never()).postWithStatus(anyString(), anyMap(), anyString(), anyString());
    }
}
