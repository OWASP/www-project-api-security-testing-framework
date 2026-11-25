package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UnsafeConsumptionOfApisTestCase} (OWASP API10:2023).
 *
 * <p>Key behavioural notes from the implementation:
 * <ul>
 *   <li>{@code testInjectionViaIntegrationEndpoints} only runs on paths containing integration
 *       patterns (webhook, proxy, integration, external, callback, third-party, import, export …).
 *       The pattern "49" is explicitly excluded from injection detection to avoid false positives.</li>
 *   <li>{@code testOpenRedirect} only runs on GET endpoints, uses a non-following HTTP client,
 *       and requires an absolute {@code Location} whose host is the injected attacker domain
 *       (relative / same-host Locations are not open redirects).</li>
 *       patterns (webhook, proxy, integration, external, callback, third-party, import, export …).</li>
 *   <li>SSTI uses a unique {@code 1337*1337=1787569} marker across template syntaxes; pure echo
 *       of the expression without evaluation is not reported, and a marker already present in the
 *       baseline is ignored.</li>
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
    @DisplayName("Should detect open redirect when Location header points at attacker host")
    void testOpenRedirectDetected() throws IOException {
        // GET endpoint — testOpenRedirect only fires on GET
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://api.example.com");

        // 302 response with Location pointing to attacker domain
        HttpResponse redirectResponse = new HttpResponse(
                302,
                "",
                Map.of("Location", List.of("https://evil-attacker.example.com/phishing"))
        );

        when(httpClient.getWithStatusNoRedirect(anyString(), anyMap()))
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
        endpoint.setBaseUrl("https://api.example.com");
        HttpResponse redirectResponse = new HttpResponse(302, "",
                Map.of("Location", List.of("https://evil-attacker.example.com/cb?access_token=s3cr3tvalue&next=/home")));
        when(httpClient.getWithStatusNoRedirect(anyString(), anyMap())).thenReturn(redirectResponse);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        Finding f = findings.stream().filter(x -> x.getTitle().contains("Redirect")).findFirst().orElseThrow();
        assertFalse(f.getEvidence().contains("s3cr3tvalue"), "Token value must not appear in evidence");
        assertTrue(f.getEvidence().contains("evil-attacker.example.com"), "Redirect target should stay");
        assertTrue(f.getEvidence().contains("next=/home"), "Non-token parameters should stay");
    }

    @Test
    @DisplayName("Should NOT report open redirect for a relative Location header")
    void testNoOpenRedirectForRelativeLocation() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://api.example.com");

        when(httpClient.getWithStatusNoRedirect(anyString(), anyMap()))
                .thenReturn(new HttpResponse(302, "", Map.of("Location", List.of("/login?next=/home"))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Redirect")),
                "Relative Location is not an open redirect");
    }

    @ParameterizedTest
    @ValueSource(strings = {"//evil-attacker.example.com/phishing", "/\\evil-attacker.example.com/phishing",
            "\\\\evil-attacker.example.com/phishing"})
    @DisplayName("Should detect scheme-relative open redirects that browsers resolve to the attacker host")
    void testSchemeRelativeOpenRedirectDetected(String location) throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://api.example.com");
        when(httpClient.getWithStatusNoRedirect(anyString(), anyMap()))
                .thenReturn(new HttpResponse(302, "", Map.of("Location", List.of(location))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Redirect")),
                "Location " + location + " leaves the scanned host");
    }

    @Test
    @DisplayName("Should NOT report open redirect when Location host is not the injected attacker host")
    void testNoOpenRedirectForUnrelatedExternalHost() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://api.example.com");

        when(httpClient.getWithStatusNoRedirect(anyString(), anyMap()))
                .thenReturn(new HttpResponse(302, "",
                        Map.of("Location", List.of("https://other.example.org/path"))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Redirect")),
                "Location must point at the injected attacker host");
    }

    @Test
    @DisplayName("Should NOT report open redirect when server returns 200 with no attacker Location header")
    void testNoOpenRedirectWhenLocationIsSafe() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://api.example.com");

        // Server returns 200 — not a redirect, so no open-redirect finding
        when(httpClient.getWithStatusNoRedirect(anyString(), anyMap()))
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
    @ParameterizedTest(name = "SSTI detection for {1}: {0}")
    @CsvSource({
            "'{{1337*1337}}', Jinja2/Twig/Nunjucks",
            "'${1337*1337}', Spring EL/JSP EL/FreeMarker",
            "'<%= 1337*1337 %>', ERB/EJS",
            "'#{1337*1337}', Ruby string interp/Thymeleaf legacy/Pug",
            "'*{1337*1337}', Thymeleaf selection",
            "'[[${1337*1337}]]', Thymeleaf inline",
            "'@(1337*1337)', Razor"
    })
    @DisplayName("Should detect SSTI when unique marker is evaluated for each template syntax")
    void testSstiDetectedPerSyntax(String payload, String engineFamily) throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    String body = inv.getArgument(3);
                    if (body.contains(payload)) {
                        // Evaluation: marker present; expression may also be echoed
                        return new HttpResponse(200,
                                "{\"out\":\"1787569 also saw " + payload + "\"}", Map.of());
                    }
                    return new HttpResponse(200, "{\"accepted\":true}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        Finding ssti = findings.stream()
                .filter(f -> f.getTitle().contains("Template Injection"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected SSTI finding for " + payload));
        assertEquals(Severity.HIGH, ssti.getSeverity());
        assertTrue(ssti.getEvidence().contains(engineFamily), "Evidence should name engine family");
        assertTrue(ssti.getEvidence().contains("1787569"));
        assertTrue(ssti.getEvidence().contains(payload));
    }

    @Test
    @DisplayName("GET SSTI probes percent-encode '#' so '#{...}' is not cut off as a URL fragment")
    void testSstiGetProbeEncodesHash() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "GET");
        List<String> urls = new java.util.ArrayList<>();
        when(httpClient.getWithStatus(anyString(), anyMap())).thenAnswer(inv -> {
            urls.add(inv.getArgument(0));
            return new HttpResponse(200, "{\"accepted\":true}", Map.of());
        });

        testCase.execute(endpoint, httpClient);

        assertTrue(urls.stream().anyMatch(u -> u.contains("data=%23{1337*1337}")),
                "the #{} probe must reach the server intact: " + urls);
        assertTrue(urls.stream().noneMatch(u -> u.contains("#")), "no raw '#' in any probe URL: " + urls);
    }

    @Test
    @DisplayName("Should NOT report SSTI when 1787569 already appears in the baseline response")
    void testNoSstiWhenMarkerInBaseline() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"n\":1787569,\"note\":\"preexisting\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Template Injection")),
                "Marker present in baseline must not produce an SSTI finding");
    }

    @Test
    @DisplayName("Should NOT report SSTI on pure echo of the expression without evaluation")
    void testNoSstiOnPureEcho() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/webhook", "POST");
        AtomicInteger calls = new AtomicInteger();

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    String body = inv.getArgument(3);
                    calls.incrementAndGet();
                    if (body.contains("1337*1337") || body.contains("{{") || body.contains("${")) {
                        // Echo the raw expression/payload only — no evaluated marker
                        return new HttpResponse(200, "{\"echo\":\"" + body.replace("\"", "\\\"") + "\"}", Map.of());
                    }
                    return new HttpResponse(200, "{\"accepted\":true}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Template Injection")),
                "Pure echo without 1787569 must not produce an SSTI finding");
        assertTrue(calls.get() > 0);
    }
}
