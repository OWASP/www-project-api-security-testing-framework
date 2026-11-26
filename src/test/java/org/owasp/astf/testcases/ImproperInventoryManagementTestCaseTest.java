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
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ImproperInventoryManagementTestCase} (OWASP API9:2023).
 *
 * <p>Important setup constraints derived from the implementation:
 * <ul>
 *   <li>{@code testOldApiVersions} only runs when the endpoint path matches {@code /v\d+/} AND
 *       {@code endpoint.getBaseUrl()} is non-null/non-empty.</li>
 *   <li>{@code testExposedDocumentation} runs once per base URL per scan (first endpoint seen
 *       for that base), regardless of whether {@code "/"} is in the endpoint list.</li>
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
    @DisplayName("Should NOT flag deprecated version/shadow endpoints on an SPA/reverse-proxy HTML fallback (regression)")
    void testNoOldVersionFindingOnHtmlFallback() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v2/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // A catch-all SPA/reverse-proxy returns 200 text/html for every guessed old-version
        // or shadow path — this must not be read as a real deprecated/shadow endpoint.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "<html><body>App</body></html>",
                        Map.of("Content-Type", List.of("text/html"))));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f ->
                        f.getTitle().contains("Deprecated") || f.getTitle().contains("Shadow")),
                "Should not flag deprecated/shadow endpoints when the response is an HTML SPA fallback page");
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

        // The fallback-baseline probe (a deliberately nonexistent path) returns 404/empty;
        // real documentation paths return 200 with OpenAPI spec content. They must differ,
        // otherwise the baseline-diff guard (added to avoid SPA-fallback false positives)
        // would treat the doc content as "just the generic fallback page".
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenReturn(notFound());
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenReturn(ok("{\"openapi\":\"3.0.0\",\"paths\":{}}"));

        // The target answers the same without credentials as with them.
        OpenTargetStubs.answerNoAuthLikeCredentialed(httpClient);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect exposed API documentation");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "Finding should reference exposed documentation");
    }

    @Test
    @DisplayName("Should NOT flag documentation exposure when every path returns the same SPA fallback page (regression)")
    void testNoDocumentationFindingOnSpaFallback() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("https://example.com");

        // Every path, including the nonexistent-path baseline probe, returns the identical
        // generic SPA shell — none of it is real documentation content.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(ok("<html><body>App Shell</body></html>"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "Should not report documentation exposure when the content is identical to the generic fallback page");
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
    @Test
    @DisplayName("Should probe documentation endpoints when the endpoint list has no root '/' path")
    void testDocProbesRunWithoutRootEndpoint() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenReturn(notFound());

        when(httpClient.getWithStatusNoAuth(argThat(url -> url != null && url.contains("__astf_nonexistent_path_check__"))))
                .thenReturn(notFound());
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.contains("/openapi.json")) {
                        return ok("{\"openapi\":\"3.0.0\",\"paths\":{}}");
                    }
                    return notFound();
                });
        when(httpClient.getWithStatusNoAuth(argThat(url -> url != null && !url.contains("__astf_nonexistent_path_check__"))))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.contains("/openapi.json")) {
                        return ok("{\"openapi\":\"3.0.0\",\"paths\":{}}");
                    }
                    return notFound();
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "Grey-box lists without '/' must still trigger target-level documentation probes");
        verify(httpClient, atLeastOnce()).getWithStatusNoAuth(contains("/openapi.json"));
    }

    @Test
    @DisplayName("Should probe documentation endpoints only once across multiple endpoints of the same base URL")
    void testDocProbesRunOncePerBaseUrl() throws IOException {
        EndpointInfo first = new EndpointInfo("/api/users", "GET");
        first.setBaseUrl("https://example.com");
        EndpointInfo second = new EndpointInfo("/api/orders", "GET");
        second.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenReturn(notFound());

        when(httpClient.getWithStatusNoAuth(argThat(url -> url != null && url.contains("__astf_nonexistent_path_check__"))))
                .thenReturn(notFound());
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenReturn(ok("{\"openapi\":\"3.0.0\",\"paths\":{}}"));
        when(httpClient.getWithStatusNoAuth(argThat(url -> url != null && !url.contains("__astf_nonexistent_path_check__"))))
                .thenReturn(ok("{\"openapi\":\"3.0.0\",\"paths\":{}}"));

        List<Finding> firstFindings = testCase.execute(first, httpClient);
        clearInvocations(httpClient);
        List<Finding> secondFindings = testCase.execute(second, httpClient);

        assertTrue(firstFindings.stream().anyMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "First endpoint for a base URL must run documentation probes");
        assertTrue(secondFindings.stream().noneMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "Second endpoint of the same base URL must not repeat documentation findings");
        verify(httpClient, never()).getWithStatus(contains("/openapi.json"), anyMap());
        verify(httpClient, never()).getWithStatusNoAuth(contains("/openapi.json"));
    }

    @Test
    @DisplayName("Should still probe documentation endpoints when '/' is present in the endpoint list")
    void testDocProbesStillRunWhenRootPresent() throws IOException {
        EndpointInfo root = new EndpointInfo("/", "GET");
        root.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenReturn(notFound());

        when(httpClient.getWithStatusNoAuth(argThat(url -> url != null && url.contains("__astf_nonexistent_path_check__"))))
                .thenReturn(notFound());
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("__astf_nonexistent_path_check__")), anyMap()))
                .thenReturn(ok("{\"openapi\":\"3.0.0\",\"paths\":{}}"));
        when(httpClient.getWithStatusNoAuth(argThat(url -> url != null && !url.contains("__astf_nonexistent_path_check__"))))
                .thenReturn(ok("{\"openapi\":\"3.0.0\",\"paths\":{}}"));

        List<Finding> findings = testCase.execute(root, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Documentation")
                        || f.getTitle().contains("Exposed")),
                "Root endpoint '/' must still trigger documentation probes exactly once");
    }
}
