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
    @DisplayName("Should handle exceptions during testing")
    void testExceptionHandling() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Network error"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }
}
