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
 * Unit tests for {@link ImproperInventoryManagementTestCase} (OWASP API9:2023).
 *
 * <p>Important setup constraints derived from the implementation:
 * <ul>
 *   <li>{@code testOldApiVersions} only runs when the endpoint path matches {@code /v\d+/} AND
 *       {@code endpoint.getBaseUrl()} is non-null/non-empty.</li>
 *   <li>{@code testExposedDocumentation} only runs when {@code baseUrl} is non-empty AND
 *       the path is {@code "/"} or {@code ""} (root endpoint guard).</li>
 * </ul>
 */
@DisplayName("Improper Inventory Management Test Case Tests")
class ImproperInventoryManagementTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private ImproperInventoryManagementTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new ImproperInventoryManagementTestCase();
    }

    // -------------------------------------------------------------------------
    // Helper factories
    // -------------------------------------------------------------------------

    private static HttpResponse ok(String body) {
        return new HttpResponse(200, body, Map.of());
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
        assertEquals("ASTF-API9-2023", testCase.getId());
        assertEquals("Improper Inventory Management", testCase.getName());
    }

    @Test
    @DisplayName("Should detect deprecated/shadow API version when old version path returns 200")
    void testOldVersionDetected() throws IOException {
        // Path must match /v\d+/ so the version regex fires, and baseUrl must be set.
        EndpointInfo endpoint = new EndpointInfo("/api/v2/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // Any GET call (for old version paths like /api/v1/users or shadow paths like /beta/users)
        // returns 200 with a body that looks like an API spec — triggers the finding.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(ok("{\"swagger\":\"2.0\",\"paths\":{}}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect deprecated or shadow API versions");
        assertTrue(
                findings.stream().anyMatch(f ->
                        f.getTitle().contains("Deprecated") || f.getTitle().contains("Shadow")),
                "Finding should reference deprecated or shadow API");
    }

    @Test
    @DisplayName("Should return no findings when shadow/old version paths return 404")
    void testNoFindingWhenShadowPathReturns404() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v2/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // All probed old/shadow paths return 404 — nothing is accessible
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(notFound());

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f ->
                        f.getTitle().contains("Deprecated") || f.getTitle().contains("Shadow")),
                "Should not detect version issues when old paths return 404");
    }

    @Test
    @DisplayName("Should report LOW finding when documentation endpoint is publicly exposed")
    void testExposedDocumentationDetected() throws IOException {
        // testExposedDocumentation only fires for root-level paths ("/" or "").
        // The path must be "/" or "" for the guard condition to pass.
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        // Documentation paths return 200 with OpenAPI spec content
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(ok("{\"openapi\":\"3.0.0\",\"paths\":{}}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect exposed API documentation");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "Finding should reference exposed documentation");
    }

    @Test
    @DisplayName("Should return no documentation finding when doc endpoints return 404")
    void testNoDocumentationFindingWhenNotExposed() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        // All documentation path probes return 404
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(notFound());

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "Should not report documentation findings when endpoints return 404");
    }

    @Test
    @DisplayName("Should handle IOException gracefully and not propagate the exception")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v2/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        assertNotNull(findings);
    }
}
