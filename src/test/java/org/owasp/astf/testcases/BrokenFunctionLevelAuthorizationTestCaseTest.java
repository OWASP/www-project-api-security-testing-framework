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

@DisplayName("Broken Function Level Authorization Test Case Tests")
class BrokenFunctionLevelAuthorizationTestCaseTest {

    @Mock private HttpClient httpClient;
    private BrokenFunctionLevelAuthorizationTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenFunctionLevelAuthorizationTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-API5-2023", testCase.getId());
        assertEquals("Broken Function Level Authorization", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should detect accessible admin endpoint")
    void testAdminEndpointAccessible() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.contains("/admin")) {
                        return new HttpResponse(200, "{\"users\":[], \"admin\":true}", Map.of());
                    }
                    return new HttpResponse(200, "{\"users\":[]}", Map.of());
                });
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                f.getTitle().contains("Administrative") || f.getTitle().contains("Endpoint")),
                "Should detect accessible admin endpoint");
    }

    @Test
    @DisplayName("Should detect HTTP method escalation")
    void testHttpMethodEscalation() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // GET works, DELETE also works (vulnerability)
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of())); // Admin not found
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"updated\":true}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));

        // For the GET endpoint itself (used in method escalation test)
        when(httpClient.getWithStatus(eq("https://example.com/api/users"), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"users\":[]}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                f.getTitle().contains("Method") || f.getTitle().contains("Authorization")),
                "Should detect HTTP method escalation");
    }

    @Test
    @DisplayName("Should return empty when admin endpoints return 401/403")
    void testAdminEndpointReturns401() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // All requests properly require authentication
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not find issues when auth is enforced");
    }

    @Test
    @DisplayName("Should handle exceptions gracefully")
    void testExceptionHandling() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }
}
