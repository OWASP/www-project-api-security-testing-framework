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

@DisplayName("Unrestricted Resource Consumption Test Case Tests")
class UnrestrictedResourceConsumptionTestCaseTest {

    @Mock private HttpClient httpClient;
    private UnrestrictedResourceConsumptionTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new UnrestrictedResourceConsumptionTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-API4-2023", testCase.getId());
        assertEquals("Unrestricted Resource Consumption", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should detect missing rate limiting")
    void testMissingRateLimit() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // All requests succeed with no 429
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"users\":[]}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Rate Limiting")),
                "Should detect missing rate limiting");
    }

    @Test
    @DisplayName("Should not flag endpoints with proper rate limiting")
    void testRateLimitingPresent() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // Returns 429 after a few requests
        final int[] count = {0};
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    count[0]++;
                    if (count[0] >= 5) {
                        return new HttpResponse(429, "{\"error\":\"Too Many Requests\"}", Map.of());
                    }
                    return new HttpResponse(200, "{\"users\":[]}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Rate Limiting")),
                "Should not flag endpoints with rate limiting");
    }

    @Test
    @DisplayName("Should not test rate limiting on non-GET endpoints")
    void testSkipsNonGetForRateLimit() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "POST");

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Rate limiting test is only for GET; no requests should be made
        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Rate Limiting")),
                "Should not test rate limiting on POST endpoints");
    }

    @Test
    @DisplayName("Should handle exceptions during rate limit testing")
    void testExceptionHandling() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection failed"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }
}
