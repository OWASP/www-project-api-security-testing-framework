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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@DisplayName("Security Misconfiguration Test Case Tests")
class SecurityMisconfigurationTestCaseTest {

    @Mock private HttpClient httpClient;
    private SecurityMisconfigurationTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new SecurityMisconfigurationTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-API8-2023", testCase.getId());
        assertEquals("Security Misconfiguration", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should detect missing security headers")
    void testMissingSecurityHeaders() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");

        // Response with no security headers
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"value\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                f.getTitle().contains("Missing Security") || f.getTitle().contains("Headers")),
                "Should detect missing security headers");
    }

    @Test
    @DisplayName("Should not flag missing headers when endpoint returns 404")
    void testNoFindingsFor404() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/nonexistent", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{\"error\":\"not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Missing Security")),
                "Should not flag 404 responses for missing headers");
    }

    @Test
    @DisplayName("Should detect wildcard CORS policy")
    void testWildcardCors() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{}", Map.of(
                        "Access-Control-Allow-Origin", List.of("*"))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("CORS")),
                "Should detect wildcard CORS");
    }

    @Test
    @DisplayName("Should detect overly permissive CORS that reflects arbitrary origin")
    void testArbitraryOriginReflected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{}", Map.of(
                        "Access-Control-Allow-Origin", List.of("https://evil-attacker.com"))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("CORS")),
                "Should detect reflected-origin CORS misconfiguration");
    }

    @Test
    @DisplayName("Should detect verbose error messages with stack traces")
    void testVerboseErrors() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        String stackTrace = "{\"error\":\"Internal Server Error\",\"details\":\"at org.springframework.Exception at java.lang.NullPointerException\"}";

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(500, stackTrace, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                f.getTitle().contains("Verbose") || f.getTitle().contains("Error")),
                "Should detect verbose error messages");
    }

    @Test
    @DisplayName("Should detect exposed debug endpoints")
    void testDebugEndpoints() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.contains("/actuator")) {
                        return new HttpResponse(200, "{\"status\":\"UP\",\"diskSpace\":{\"total\":500}}", Map.of());
                    }
                    return new HttpResponse(404, "{}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Debug") || f.getTitle().contains("Endpoint")),
                "Should detect exposed debug/actuator endpoints");
    }

    @Test
    @DisplayName("Should flag conventionally-public endpoints (health/status/ping) as LOW, not HIGH")
    void testConventionallyPublicEndpointGetsLowSeverity() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.endsWith("/health")) {
                        return new HttpResponse(200, "{\"status\":\"UP\"}", Map.of());
                    }
                    return new HttpResponse(404, "{}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        findings.stream()
                .filter(f -> f.getTitle().contains("Debug") && f.getEndpoint() != null && f.getEndpoint().contains("/health"))
                .findFirst()
                .ifPresentOrElse(
                        f -> assertEquals(Severity.LOW, f.getSeverity(),
                                "A conventionally-public health endpoint should be LOW severity, not HIGH"),
                        () -> fail("Expected a finding for the /health endpoint"));
    }

    @Test
    @DisplayName("Should NOT flag a generic error message that merely mentions 'key' without disclosing a value")
    void testNoVerboseErrorFalsePositiveOnGenericMessage() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        String genericError = "{\"error\":\"invalid API key\"}";

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(500, genericError, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Verbose")),
                "Should not flag a generic 'invalid API key' message as verbose error disclosure");
    }

    @Test
    @DisplayName("Should still flag a genuine disclosed credential value in an error message")
    void testVerboseErrorStillDetectedForRealDisclosure() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        String realDisclosure = "{\"error\":\"db connection failed\",\"password\": \"hunter2\"}";

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(500, realDisclosure, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Verbose")),
                "Should still flag a genuine 'password: value' disclosure in an error response");
    }

    @Test
    @DisplayName("Should NOT report any debug endpoint when the target serves an SPA catch-all for every path (regression)")
    void testNoDebugEndpointFindingsOnHtmlCatchAll() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        // A single-page app / reverse proxy answers 200 text/html with the same app shell for
        // every unmatched route. All 30 probed debug paths hit it, and every one of them would
        // otherwise be reported — most at HIGH severity.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "<html><body><div id=\"root\"></div></body></html>",
                        Map.of("Content-Type", List.of("text/html"))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Debug")),
                "An SPA catch-all page must not be reported as an exposed debug endpoint");
    }

    @Test
    @DisplayName("Should NOT report any debug endpoint when a gateway answers 200 with a JSON not-found envelope (regression)")
    void testNoDebugEndpointFindingsOnJsonCatchAll() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        // An API gateway default route that reports absence with a success status. The body is
        // JSON, so a content-type check alone would not screen it out.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"message\":\"Not Found\"}",
                        Map.of("Content-Type", List.of("application/json"))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Debug")),
                "A 200 response whose body says 'Not Found' must not be reported as an exposed endpoint");
    }

    @Test
    @DisplayName("Should still report a genuinely exposed debug endpoint on a catch-all target (no false negative)")
    void testRealDebugEndpointStillDetectedOnCatchAllTarget() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        HttpResponse catchAll = new HttpResponse(200, "<html><body><div id=\"root\"></div></body></html>",
                Map.of("Content-Type", List.of("text/html")));

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.endsWith("/actuator/env")) {
                        return new HttpResponse(200,
                                "{\"activeProfiles\":[\"prod\"],\"propertySources\":[{\"name\":\"systemEnvironment\"}]}",
                                Map.of("Content-Type", List.of("application/json")));
                    }
                    return catchAll;
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                        f.getTitle().contains("Debug") && f.getEndpoint() != null
                                && f.getEndpoint().contains("/actuator/env")),
                "A real actuator env dump differs from the catch-all page and must still be reported");
    }

    @Test
    @DisplayName("Should handle exceptions during testing")
    void testExceptionHandling() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Network error"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }

    // AI-Generated Code - 2026-11-25 - Auto
    // This is AI generated code
    @Test
    @DisplayName("Absent X-XSS-Protection must not produce a finding")
    void testAbsentXssProtectionNotReported() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        Map<String, List<String>> headers = requiredSecurityHeaders();
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{}", headers));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f ->
                        f.getTitle().contains("X-XSS-Protection")
                                || (f.getTitle().contains("Missing Security")
                                && f.getEvidence() != null
                                && f.getEvidence().contains("X-XSS-Protection"))),
                "Absence of deprecated X-XSS-Protection must not be reported");
    }

    @Test
    @DisplayName("X-XSS-Protection: 1; mode=block must produce a LOW finding")
    void testEnabledXssProtectionReportedAsLow() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        Map<String, List<String>> headers = requiredSecurityHeaders();
        headers.put("X-XSS-Protection", List.of("1; mode=block"));
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{}", headers));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        Finding xss = findings.stream()
                .filter(f -> f.getTitle().contains("X-XSS-Protection"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected a finding for enabled X-XSS-Protection"));
        assertEquals(Severity.LOW, xss.getSeverity());
    }

    @Test
    @DisplayName("X-XSS-Protection: 0 must not produce a finding")
    void testXssProtectionZeroNotReported() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        Map<String, List<String>> headers = requiredSecurityHeaders();
        headers.put("X-XSS-Protection", List.of("0"));
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{}", headers));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("X-XSS-Protection")),
                "X-XSS-Protection: 0 is the recommended disable value and must not be flagged");
    }

    @Test
    @DisplayName("Authenticated 2xx without Cache-Control no-store must produce a LOW finding")
    void testAuthenticatedMissingNoStoreReportedAsLow() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        when(httpClient.getConfiguredBearerToken()).thenReturn("test-token");
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"secret\":1}", requiredSecurityHeaders()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        Finding cache = findings.stream()
                .filter(f -> f.getTitle().contains("Cache-Control") || f.getTitle().contains("no-store"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected missing no-store finding"));
        assertEquals(Severity.LOW, cache.getSeverity());
    }

    @Test
    @DisplayName("Authenticated 2xx with Cache-Control: no-store must not produce a cache finding")
    void testAuthenticatedWithNoStoreNotReported() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        when(httpClient.getConfiguredBearerToken()).thenReturn("test-token");
        Map<String, List<String>> headers = requiredSecurityHeaders();
        headers.put("Cache-Control", List.of("private, no-store"));
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"secret\":1}", headers));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f ->
                        f.getTitle().contains("Cache-Control") || f.getTitle().contains("no-store")),
                "Cache-Control containing no-store must satisfy the authenticated-response check");
    }

    @Test
    @DisplayName("Authenticated 2xx with only Cache-Control: no-cache must produce a LOW finding")
    void testAuthenticatedNoCacheOnlyReportedAsLow() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        when(httpClient.getConfiguredBearerToken()).thenReturn("test-token");
        Map<String, List<String>> headers = requiredSecurityHeaders();
        headers.put("Cache-Control", List.of("no-cache"));
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"secret\":1}", headers));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        Finding cache = findings.stream()
                .filter(f -> f.getTitle().contains("Cache-Control") || f.getTitle().contains("no-store"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no-cache alone must not satisfy the check"));
        assertEquals(Severity.LOW, cache.getSeverity());
    }

    private static Map<String, List<String>> requiredSecurityHeaders() {
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("X-Content-Type-Options", List.of("nosniff"));
        headers.put("X-Frame-Options", List.of("DENY"));
        headers.put("Strict-Transport-Security", List.of("max-age=31536000"));
        headers.put("Content-Security-Policy", List.of("default-src 'self'"));
        return headers;
    }
}
