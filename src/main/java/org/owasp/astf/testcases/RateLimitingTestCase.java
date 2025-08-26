package org.owasp.astf.testcases;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Tests for Rate Limiting vulnerabilities.
 *
 * This test case sends multiple requests in rapid succession to the API endpoint
 * and checks if rate limiting is properly enforced.
 */
public class RateLimitingTestCase implements TestCase {

    private static final Logger logger = LogManager.getLogger(RateLimitingTestCase.class);

    private static final int REQUEST_COUNT = 20;
    private static final List<String> SAFE_ENDPOINTS = List.of(
            "/api/health",
            "/api/status",
            "/api/public/info"
        );

    @Override
    public String getId() {
        return "ASTF-RL-2025";
    }

    @Override
    public String getName() {
        return "Rate Limiting";
    }

    @Override
    public String getDescription() {
        return """
                Sends multiple requests in a short timeframe to test if the API
                enforces rate limiting to protect against brute force or abuse.
                """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);

        List<Finding> findings = new ArrayList<>();
        Map<String, String> headers = Map.of("Content-Type", "application/json");
        String requestBody = "{\"key\":\"value\"}";
        boolean rateLimitTriggered = false;

        for (int i = 0; i < REQUEST_COUNT; i++) {
            try {
                String response;

                switch (endpoint.getMethod().toUpperCase()) {
                    case "POST" -> response = httpClient.post(endpoint.getPath(), headers, "application/json", requestBody);
                    case "GET" -> response = httpClient.get(endpoint.getPath(), headers);
                    case "PUT" -> response = httpClient.put(endpoint.getPath(), headers, "application/json", requestBody);
                    case "DELETE" -> response = httpClient.delete(endpoint.getPath(), headers);
                    default -> {
                        logger.warn("Unsupported HTTP method {} for endpoint {}", endpoint.getMethod(), endpoint.getPath());
                        return findings;
                    }
                }

                // Check if the response indicates rate limiting
                // This might be HTTP 429 Too Many Requests or some error message in response body
                if (response != null && (response.contains("429") || response.toLowerCase().contains("rate limit") || response.toLowerCase().contains("too many requests"))) {
                    rateLimitTriggered = true;
                    break;
                }

            } catch (IOException e) {
                logger.error("Request failed on attempt {}: {}", i + 1, e.getMessage());
            }
        }

        if (rateLimitTriggered) {
            findings.add(new Finding(
                UUID.randomUUID().toString(),
                "Rate Limiting Enforced",
                "The endpoint correctly enforced rate limiting after multiple rapid requests.",
                Severity.INFO,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "No action needed."
            ));
        } else if (!isSafeToSkipRateLimiting(endpoint.getPath())) {
            findings.add(new Finding(
                UUID.randomUUID().toString(),
                "Missing or Ineffective Rate Limiting",
                "The endpoint did not enforce rate limiting after multiple rapid requests.",
                Severity.HIGH,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Implement rate limiting to protect API endpoints from brute force and abuse."
            ));
        } else {
            logger.info("Skipping finding for non-sensitive endpoint: {}", endpoint.getPath());
        }

        return findings;
    }

    private boolean isSafeToSkipRateLimiting(String path) {
        return SAFE_ENDPOINTS.stream().anyMatch(path::startsWith);
    }
}
