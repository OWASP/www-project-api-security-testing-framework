package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

/**
 * Tests for API4:2023 Unrestricted Resource Consumption.
 *
 * This test case checks for APIs that do not properly manage or restrict resource usage,
 * making them vulnerable to denial of service attacks. This includes lack of rate limiting,
 * missing pagination, unbounded requests, and other resource consumption vulnerabilities
 * according to the OWASP API Security Top 10 2023.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/">OWASP API Security Top 10 2023: API4 Unrestricted Resource Consumption</a>
 */
public class ResourcesAndRateLimitingTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(ResourcesAndRateLimitingTestCase.class);

    // Thresholds for testing
    private static final int RATE_LIMIT_TEST_REQUESTS = 20;
    private static final int MAX_THREADS = 5;
    private static final int REQUEST_INTERVAL_MS = 100;
    private static final int PAGINATION_LIMIT_TEST = 1000;
    private static final int LARGE_PAYLOAD_SIZE_KB = 500;

    @Override
    public String getId() {
        return "ASTF-API4-2023";
    }

    @Override
    public String getName() {
        return "Unrestricted Resource Consumption";
    }

    @Override
    public String getDescription() {
        return """
               Tests for resource consumption vulnerabilities such as missing rate limiting,
               unbounded result sets, lack of pagination controls, and susceptibility to
               resource-intensive operations that could lead to denial of service.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        try {
            // Test for rate limiting vulnerabilities
            findings.addAll(testRateLimiting(endpoint, httpClient));
    
            // Test for unbounded result sets and pagination issues
            findings.addAll(testUnboundedResults(endpoint, httpClient));
    
            // Test for large payload handling
            findings.addAll(testLargePayloads(endpoint, httpClient));
    
            // Test for resource-intensive operations
            findings.addAll(testResourceIntensiveOperations(endpoint, httpClient));
        } catch (Exception e) {
            logger.error("Error executing test case on endpoint {}: {}", endpoint, e.getMessage());
            logger.debug("Stack trace:", e);
            
            // Add a general finding about the need for resource limiting when an exception occurs
            Finding finding = new Finding(
                UUID.randomUUID().toString(),
                "Resource Consumption Testing Failed",
                "Testing for unrestricted resource consumption failed, which could indicate the API lacks proper error handling for abnormal requests.",
                Severity.LOW,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Implement proper resource limiting, request validation, and error handling for all API endpoints."
            );
            
            findings.add(finding);
        }

        return findings;
    }

    /**
     * Tests the API endpoint for proper rate limiting implementation.
     * This is done by sending multiple requests in rapid succession and
     * observing if any restrictions are imposed after a certain threshold.
     *
     * @param endpoint The endpoint to test
     * @param httpClient The HTTP client to use for requests
     * @return A list of findings related to rate limiting issues
     */
    private List<Finding> testRateLimiting(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        
        try {
            String fullUrl = "https://example.com" + endpoint.getPath();
            ExecutorService executor = Executors.newFixedThreadPool(MAX_THREADS);
            List<Future<?>> futures = new ArrayList<>();
            AtomicBoolean rateLimitDetected = new AtomicBoolean(false);
            
            // Send multiple requests in rapid succession
            for (int i = 0; i < RATE_LIMIT_TEST_REQUESTS; i++) {
                Future<?> future = executor.submit(() -> {
                    try {
                        Map<String, String> headers = Map.of(
                            "X-Request-ID", UUID.randomUUID().toString(),
                            "Authorization", "Bearer test-token"
                        );
                        
                        String response = null;
                        switch (endpoint.getMethod().toUpperCase()) {
                            case "GET" -> response = httpClient.get(fullUrl, headers);
                            case "POST" -> response = httpClient.post(fullUrl, headers, "application/json", "{}");
                            case "PUT" -> response = httpClient.put(fullUrl, headers, "application/json", "{}");
                            case "DELETE" -> response = httpClient.delete(fullUrl, headers);
                        }
                        
                        // Since we can't directly access response headers or status codes from the HttpClient
                        // We'll look for indicators in the response content instead
                        if (response != null && (
                            response.toLowerCase().contains("rate limit") ||
                            response.toLowerCase().contains("too many requests") ||
                            response.toLowerCase().contains("quota exceeded") ||
                            response.toLowerCase().contains("try again later") ||
                            response.toLowerCase().contains("throttled"))) {
                            rateLimitDetected.set(true);
                        }
                    } catch (Exception e) {
                        if (e.getMessage() != null && (
                            e.getMessage().contains("429") || 
                            e.getMessage().toLowerCase().contains("rate limit") ||
                            e.getMessage().toLowerCase().contains("too many requests") ||
                            e.getMessage().toLowerCase().contains("throttled"))) {
                            rateLimitDetected.set(true);
                        }
                        logger.debug("Error during rate limit testing: {}", e.getMessage());
                    }
                    
                    // Add slight delay between requests
                    try {
                        Thread.sleep(REQUEST_INTERVAL_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
                
                futures.add(future);
            }
            
            // Wait for all requests to complete
            for (Future<?> future : futures) {
                try {
                    future.get(30, TimeUnit.SECONDS);
                } catch (Exception e) {
                    logger.debug("Exception waiting for rate limit test to complete: {}", e.getMessage());
                }
            }
            
            executor.shutdown();
            
            // If no rate limiting was detected, report a finding
            if (!rateLimitDetected.get()) {
                Finding finding = new Finding(
                    UUID.randomUUID().toString(),
                    "Missing Rate Limiting",
                    "The API endpoint does not appear to implement rate limiting, which could allow excessive usage and potential DoS attacks.",
                    Severity.HIGH,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Implement appropriate rate limiting strategies such as token bucket, fixed window, or sliding window counters. Add rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After) and return 429 Too Many Requests when limits are exceeded."
                );
                
                findings.add(finding);
            }
            
        } catch (Exception e) {
            logger.debug("Error testing rate limiting on endpoint {}: {}", endpoint, e.getMessage());
        }
        
        return findings;
    }

    /**
     * Tests for unbounded result sets, particularly in GET requests.
     * APIs should implement pagination to limit the amount of data returned
     * in a single request.
     *
     * @param endpoint The endpoint to test
     * @param httpClient The HTTP client to use for requests
     * @return A list of findings related to unbounded result sets
     */
    private List<Finding> testUnboundedResults(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        // Focus on GET requests which are likely to return collections
        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        try {
            String fullUrl = "https://example.com" + endpoint.getPath();
            Map<String, String> headers = Map.of("Authorization", "Bearer test-token");
            
            // Test with no pagination parameters
            String response = httpClient.get(fullUrl, headers);
            
            // Check for large response size that might indicate unbounded results
            int responseSize = response != null ? response.length() : 0;
            
            // Try to determine if pagination is implemented
            boolean paginationImplemented = false;
            
            // Test with common pagination parameters
            List<Map<String, String>> paginationTests = List.of(
                Map.of("page", "1", "limit", String.valueOf(PAGINATION_LIMIT_TEST)),
                Map.of("page", "1", "per_page", String.valueOf(PAGINATION_LIMIT_TEST)),
                Map.of("offset", "0", "limit", String.valueOf(PAGINATION_LIMIT_TEST))
            );
            
            for (Map<String, String> params : paginationTests) {
                String queryString = params.entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .reduce((a, b) -> a + "&" + b)
                    .orElse("");
                
                String urlWithParams = fullUrl + (fullUrl.contains("?") ? "&" : "?") + queryString;
                String paginatedResponse = httpClient.get(urlWithParams, headers);
                
                // Since we can't access response headers directly, we'll only check the response body
                // for pagination indicators
                
                // Check if response contains pagination metadata
                if (paginatedResponse != null && 
                    (paginatedResponse.contains("\"page\":") || 
                     paginatedResponse.contains("\"pagination\":") ||
                     paginatedResponse.contains("\"total_pages\":") ||
                     paginatedResponse.contains("\"count\":") ||
                     paginatedResponse.contains("\"total\":") ||
                     paginatedResponse.contains("\"next\":") ||
                     paginatedResponse.contains("\"prev\":")
                    )) {
                    paginationImplemented = true;
                    break;
                }
            }
            
            // If response is large and no pagination was detected
            if (responseSize > 100000 && !paginationImplemented) {
                Finding finding = new Finding(
                    UUID.randomUUID().toString(),
                    "Unbounded Result Set",
                    "The API endpoint returns large result sets without implementing pagination, which can lead to excessive resource consumption.",
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Implement pagination for all endpoints that return collections. Include pagination parameters (page/offset and limit) and provide metadata about total results and pages."
                );
                
                findings.add(finding);
            }
            
        } catch (Exception e) {
            logger.debug("Error testing unbounded results on endpoint {}: {}", endpoint, e.getMessage());
        }
        
        return findings;
    }

    
}