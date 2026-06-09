package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@DisplayName("Rate Limiting Test Case Tests")
class RateLimitingTest {

    @Mock
    private HttpClient httpClient;

    private RateLimitingTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new RateLimitingTestCase();
    }

    @ParameterizedTest(name = "{index}: {0} {1} -> expected: {3}")
    @MethodSource("provideEndpoints")
    @DisplayName("Should detect or skip rate limiting based on server response")
    void testRateLimitingDetectionWithProvider(
        String description,
        EndpointInfo endpoint,
        String mockResponse,
        String expectedFindingTitle
    ) throws IOException {

        final int threshold = 5;
        final int totalCalls = 20;
        final String path = endpoint.getPath();
        final String method = endpoint.getMethod().toUpperCase();

        final int[] counter = {0};
        var answer = (org.mockito.stubbing.Answer<String>) invocation -> {
            counter[0]++;
            if (counter[0] >= threshold && mockResponse.contains("Too Many Requests")) {
                return "{\"error\":\"Too Many Requests\",\"status\":429}";
            }
            return "{\"message\":\"ok\"}";
        };

        switch (method) {
            case "GET" -> when(httpClient.get(eq(path), anyMap())).thenAnswer(answer);
            case "POST" -> when(httpClient.post(eq(path), anyMap(), anyString(), anyString())).thenAnswer(answer);
            case "PUT" -> when(httpClient.put(eq(path), anyMap(), anyString(), anyString())).thenAnswer(answer);
            case "DELETE" -> when(httpClient.delete(eq(path), anyMap())).thenAnswer(answer);
            default -> fail("Unsupported HTTP method in test: " + method);
        }

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        if (expectedFindingTitle != null) {
            assertFalse(findings.isEmpty(), "Expected finding for: " + description);
            assertEquals(expectedFindingTitle, findings.get(0).getTitle(),
                    "Unexpected finding title for: " + description);
        } else {
            assertTrue(findings.isEmpty(), "Did not expect any findings for: " + description);
        }
    }

    private static Stream<org.junit.jupiter.params.provider.Arguments> provideEndpoints() {
        return Stream.of(
            org.junit.jupiter.params.provider.Arguments.of(
                "Rate limiting detected via 400 error on POST",
                new EndpointInfo("/api/rate-limited", "POST"),
                "{\"error\":\"invalid request\",\"status\":400}",
                "Missing or Ineffective Rate Limiting"
            ),
            org.junit.jupiter.params.provider.Arguments.of(
                "Rate limiting detected via 429 error on GET",
                new EndpointInfo("/api/rate-limited", "GET"),
                "{\"error\":\"Too Many Requests\",\"status\":429}",
                "Rate Limiting Enforced"
            ),
            org.junit.jupiter.params.provider.Arguments.of(
                "Health check endpoint - safe to skip",
                new EndpointInfo("/api/health", "GET"),
                "{\"message\":\"ok\"}",
                null
            )
        );
    }
}
