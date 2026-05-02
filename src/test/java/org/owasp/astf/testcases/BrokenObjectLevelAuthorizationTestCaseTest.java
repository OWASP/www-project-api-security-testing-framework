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

@DisplayName("Broken Object Level Authorization Test Case Tests")
class BrokenObjectLevelAuthorizationTestCaseTest {

    @Mock private HttpClient httpClient;
    private BrokenObjectLevelAuthorizationTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenObjectLevelAuthorizationTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-API1-2023", testCase.getId());
        assertEquals("Broken Object Level Authorization", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should not find issues when alternate ID returns 404")
    void testNoBolaWhenAltIdNotFound() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/123", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{\"error\":\"not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Should detect BOLA when alternate numeric ID returns 200")
    void testBolaWithNumericId() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/42", "GET");
        endpoint.setBaseUrl("https://example.com");

        // Both original and alternate IDs return 200
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"id\":1,\"name\":\"User\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertFalse(findings.isEmpty(), "Should detect BOLA");
        assertTrue(findings.get(0).getTitle().contains("Broken Object Level Authorization"));
    }

    @Test
    @DisplayName("Should return empty for paths without resource IDs")
    void testNoIdsInPath() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "No IDs in path means no BOLA test possible");
    }

    @Test
    @DisplayName("Should detect BOLA with UUID substitution")
    void testBolaWithUuid() throws IOException {
        EndpointInfo endpoint = new EndpointInfo(
                "/api/orders/550e8400-e29b-41d4-a716-446655440000", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"orderId\":\"any\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertFalse(findings.isEmpty(), "Should detect UUID-based BOLA");
    }

    @Test
    @DisplayName("Should handle exceptions gracefully")
    void testExceptionHandling() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection failed"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }
}
