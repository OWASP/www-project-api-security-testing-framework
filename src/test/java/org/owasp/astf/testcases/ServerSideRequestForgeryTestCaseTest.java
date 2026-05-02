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
 * Unit tests for {@link ServerSideRequestForgeryTestCase} (OWASP API7:2023).
 */
@DisplayName("Server Side Request Forgery Test Case Tests")
class ServerSideRequestForgeryTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private ServerSideRequestForgeryTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new ServerSideRequestForgeryTestCase();
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
        assertEquals("ASTF-API7-2023", testCase.getId());
        assertEquals("Server Side Request Forgery", testCase.getName());
    }

    @Test
    @DisplayName("Should detect SSRF when GET response body contains AWS metadata indicator 'ami-id'")
    void testSsrfDetectedInQueryParam() throws IOException {
        // GET endpoint — the test case exercises testQueryParameterSsrf
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        // Any GET call returns a body containing an SSRF indicator
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200,
                        "{\"result\":\"ami-id: ami-0abcdef1234567890\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report a finding when SSRF indicator is in the response");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("SSRF")
                        || f.getTitle().contains("Server Side Request Forgery")),
                "Finding title should reference SSRF");
    }

    @Test
    @DisplayName("Should return no findings when GET response body is clean (no SSRF indicators)")
    void testNoSsrfWhenResponseClean() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"normal\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not report findings when response contains no SSRF indicators");
    }

    @Test
    @DisplayName("Should detect SSRF when POST response body contains 'instance-id'")
    void testSsrfDetectedInBodyParam() throws IOException {
        // POST endpoint — exercises testBodyParameterSsrf
        EndpointInfo endpoint = new EndpointInfo("/api/proxy", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"response\":\"instance-id: i-1234567890abcdef0\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report a finding when SSRF indicator is in the POST response");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("SSRF")
                        || f.getTitle().contains("Server Side Request Forgery")),
                "Finding title should reference SSRF");
    }

    @Test
    @DisplayName("Should return no findings when POST returns 403 (server rejects SSRF payload)")
    void testSsrfNotDetectedWhenServerRejects() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/proxy", "POST");

        // Server rejects the request — no SSRF content is returned
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(403, "{\"error\":\"forbidden\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not report findings when server rejects the SSRF payload");
    }

    @Test
    @DisplayName("Should handle IOException gracefully and not propagate the exception")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        assertNotNull(findings);
    }
}
