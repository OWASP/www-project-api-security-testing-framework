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
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UnrestrictedAccessToSensitiveFlowsTestCase} (OWASP API6:2023).
 */
@DisplayName("Unrestricted Access to Sensitive Business Flows Test Case Tests")
class UnrestrictedAccessToSensitiveFlowsTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private UnrestrictedAccessToSensitiveFlowsTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new UnrestrictedAccessToSensitiveFlowsTestCase();
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

    private static HttpResponse rateLimited() {
        return new HttpResponse(429, "{\"error\":\"rate limited\"}", Map.of());
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should have correct ID, name, and non-null description")
    void testMetadata() {
        assertEquals("ASTF-API6-2023", testCase.getId());
        assertEquals("Unrestricted Access to Sensitive Business Flows", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should report HIGH finding when sensitive path accepts 10+ automated POST requests")
    void testSensitivePathRateLimitMissing() throws IOException {
        // /api/checkout contains "checkout" — a sensitive flow pattern
        EndpointInfo endpoint = new EndpointInfo("/api/checkout", "POST");

        // The implementation sends exactly 10 requests; mock all 10 to return 200
        HttpResponse ok = ok();
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok, ok, ok, ok, ok, ok, ok, ok, ok, ok);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report findings when rate limiting is absent");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("Rate Limiting")
                        || f.getTitle().contains("Without Rate Limiting")),
                "Should have a rate-limiting finding");
    }

    @Test
    @DisplayName("Should NOT report rate-limit finding when server returns 429 on first request")
    void testSensitivePathRateLimitPresent() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/checkout", "POST");

        // First call triggers 429 — server enforces rate limiting
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(rateLimited());

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Rate Limiting")
                        || f.getTitle().contains("Without Rate Limiting")),
                "Should NOT report rate-limit finding when 429 is returned");
    }

    @Test
    @DisplayName("Should return no findings for non-sensitive paths (skipped entirely)")
    void testNonSensitivePathSkipped() throws IOException {
        // /api/products does not contain any sensitive flow pattern
        EndpointInfo endpoint = new EndpointInfo("/api/products", "GET");

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Non-sensitive paths should produce no findings");
    }

    @Test
    @DisplayName("Should report MEDIUM finding when bot protection headers are absent on sensitive path")
    void testBotProtectionMissing() throws IOException {
        // /api/register contains "register" — a sensitive flow pattern
        EndpointInfo endpoint = new EndpointInfo("/api/register", "POST");

        // All calls (10 abuse probes + 1 bot-protection probe) return 200 with empty headers
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok());

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report findings when bot protection is absent");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("Bot Protection")),
                "Should have a bot protection finding");
    }

    @Test
    @DisplayName("Should NOT report bot protection finding when X-RateLimit-Limit header is present")
    void testBotProtectionPresent() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/register", "POST");

        // Response includes the X-RateLimit-Limit header — bot protection is in place
        HttpResponse responseWithRateLimitHeader = new HttpResponse(
                200,
                "{\"data\":\"ok\"}",
                Map.of("X-RateLimit-Limit", List.of("10"))
        );

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(responseWithRateLimitHeader);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Bot Protection")),
                "Should NOT report bot protection finding when header is present");
    }

    @Test
    @DisplayName("Should handle IOException gracefully and return empty findings")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/checkout", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        // Must not propagate the exception
        List<Finding> findings = assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        assertNotNull(findings);
    }
}
