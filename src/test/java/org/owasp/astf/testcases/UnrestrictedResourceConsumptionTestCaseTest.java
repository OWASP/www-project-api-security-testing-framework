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
    @DisplayName("Should detect rate limiting is missing even when a rejection is a 200 with a body message, not a 429 (regression)")
    void testMissingRateLimitDetectedViaBodyEvenWithout429() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // Every response is HTTP 200 with a normal-looking success body — genuinely no rate
        // limiting anywhere, never a rejection of any kind.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"users\":[]}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Rate Limiting")),
                "Should still detect missing rate limiting when every response is a genuine 200 success");
    }

    @Test
    @DisplayName("Should NOT flag missing rate limiting when a 200 response body signals rejection")
    void testNoRateLimitFindingWhen200BodySignalsRejection() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // Server returns HTTP 200 for every call, but explicitly says "rate limit exceeded" in
        // the body instead of using a 429 status — this must still count as rate limiting working.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"error\":\"rate limit exceeded, please slow down\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Rate Limiting")),
                "Should not flag missing rate limiting when the body explicitly signals a rejection");
    }

    @Test
    @DisplayName("Should flag missing pagination limit when a large page-size request returns a huge JSON array")
    void testLargePaginationLimitMissing() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        String hugeArray = "[" + "{\"id\":1,\"name\":\"user\"},".repeat(60_000) + "{\"id\":2}]";
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, hugeArray, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Missing Pagination Limit")),
                "Should flag missing pagination limit for an oversized JSON array response");
    }

    @Test
    @DisplayName("Should NOT flag missing pagination limit when the large response isn't JSON data")
    void testNoLargePaginationFindingForNonJsonBody() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // A large HTML error/fallback page, not real API data
        String hugeHtml = "<html><body>" + "error ".repeat(200_000) + "</body></html>";
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, hugeHtml, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Missing Pagination Limit")),
                "Should not flag missing pagination limit for a large non-JSON (HTML) response");
    }

    @Test
    @DisplayName("Should flag missing pagination metadata on a large collection response with no pagination indicators")
    void testMissingPaginationMetadata() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        String hugeArrayNoMetadata = "[" + "{\"id\":1,\"name\":\"user\"},".repeat(6_000) + "{\"id\":2}]";
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, hugeArrayNoMetadata, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Missing Pagination on Collection")),
                "Should flag missing pagination metadata for a large response with no pagination indicators");
    }

    @Test
    @DisplayName("Should NOT flag missing pagination metadata when the response includes pagination fields")
    void testNoMissingPaginationFindingWhenMetadataPresent() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        String hugeArrayWithMetadata = "{\"total\":6000,\"page\":1,\"users\":[" +
                "{\"id\":1,\"name\":\"user\"},".repeat(6_000) + "{\"id\":2}]}";
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, hugeArrayWithMetadata, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Missing Pagination on Collection")),
                "Should not flag missing pagination metadata when the response already includes pagination fields");
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
