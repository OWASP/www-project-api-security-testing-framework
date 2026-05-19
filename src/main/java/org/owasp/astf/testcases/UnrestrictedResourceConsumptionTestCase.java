package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

/**
 * Tests for API4:2023 Unrestricted Resource Consumption.
 *
 * APIs that do not enforce limits on the size or number of resources that can be requested
 * are vulnerable to Denial of Service (DoS) attacks and high operational costs. This includes
 * missing rate limiting, missing pagination limits, and allowing excessively large payloads.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/">OWASP API4:2023</a>
 */
public class UnrestrictedResourceConsumptionTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(UnrestrictedResourceConsumptionTestCase.class);

    private static final int RATE_LIMIT_TEST_REQUESTS = 20;
    private static final int RATE_LIMIT_THRESHOLD = 15; // 15+ successes = likely no rate limiting

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
        return "Tests for missing rate limiting, missing pagination controls, and the ability to " +
               "request excessively large data sets, which can lead to DoS conditions.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testRateLimiting(endpoint, httpClient));
        findings.addAll(testLargePaginationRequests(endpoint, httpClient));
        findings.addAll(testMissingPagination(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testRateLimiting(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        // Rate limiting on intentionally public endpoints (e.g. /api/info, /api/v1/settings.public)
        // is a DoS concern, not an authentication/data-security concern. Skip to avoid noise —
        // the user explicitly marked these as auth: false in their config.
        if (!endpoint.isRequiresAuthentication()) {
            logger.debug("Skipping rate-limit test for public endpoint {} {}", endpoint.getMethod(), endpoint.getPath());
            return findings;
        }

        int successCount = 0;
        int rateLimitedCount = 0;
        String fullUrl = endpoint.getFullUrl();

        for (int i = 0; i < RATE_LIMIT_TEST_REQUESTS; i++) {
            try {
                HttpResponse response = httpClient.getWithStatus(fullUrl, Map.of());
                if (response != null) {
                    if (response.isRateLimited()) {
                        rateLimitedCount++;
                        break; // Rate limiting is working
                    } else if (response.isSuccess()) {
                        successCount++;
                    }
                }
            } catch (Exception e) {
                logger.debug("Error during rate limit test on {}: {}", endpoint, e.getMessage());
                break;
            }
        }

        // If we got many successes without a single 429, rate limiting is likely missing
        if (successCount >= RATE_LIMIT_THRESHOLD && rateLimitedCount == 0) {
            Finding finding = new Finding(
                    UUID.randomUUID().toString(),
                    "Missing Rate Limiting",
                    String.format("The endpoint accepted %d consecutive requests without triggering " +
                            "rate limiting (HTTP 429). This makes the API vulnerable to brute force " +
                            "attacks, DoS, and excessive resource consumption.", successCount),
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Implement rate limiting using token bucket, leaky bucket, or fixed window algorithms. " +
                    "Return HTTP 429 with a Retry-After header when limits are exceeded. " +
                    "Apply limits per user, API key, or IP address as appropriate."
            );
            finding.setEvidence(successCount + " requests succeeded without rate limiting; " +
                    "no HTTP 429 response received");
            findings.add(finding);
        }

        return findings;
    }

    private List<Finding> testLargePaginationRequests(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        String path = endpoint.getPath();
        // Only test collection endpoints (no numeric ID at end)
        if (path.matches(".*/\\d+/?$")) {
            return findings;
        }

        // Try requesting an extremely large page size
        List<String> largeSizeParams = List.of("?limit=10000", "?page_size=10000", "?per_page=10000", "?count=10000");

        for (String param : largeSizeParams) {
            String testUrl = endpoint.getFullUrl() + param;
            try {
                HttpResponse response = httpClient.getWithStatus(testUrl, Map.of());
                if (response != null && response.isSuccess()) {
                    String body = response.getBody();
                    // A response body larger than 1MB suggests unbounded data return
                    if (body.length() > 1_000_000) {
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "Missing Pagination Limit - Large Response Returned",
                                "The API returned an extremely large response (" +
                                (body.length() / 1024) + " KB) when a large page size was requested. " +
                                "This indicates missing server-side pagination limits.",
                                Severity.MEDIUM,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Enforce maximum page size limits server-side. Ignore or cap client-provided " +
                                "page size parameters. Return a reasonable default when no limit is specified."
                        );
                        finding.setRequestDetails("GET " + testUrl);
                        finding.setEvidence("Response body size: " + body.length() + " bytes");
                        findings.add(finding);
                        break;
                    }
                }
            } catch (Exception e) {
                logger.debug("Error testing large pagination on {}: {}", testUrl, e.getMessage());
            }
        }

        return findings;
    }

    private List<Finding> testMissingPagination(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        String path = endpoint.getPath();
        // Only test collection endpoints
        if (path.matches(".*/\\d+/?$") || path.contains("{")) {
            return findings;
        }

        try {
            HttpResponse response = httpClient.getWithStatus(endpoint.getFullUrl(), Map.of());
            if (response == null || !response.isSuccess()) {
                return findings;
            }

            String body = response.getBody();
            boolean hasPaginationHeaders = response.hasHeader("X-Total-Count")
                    || response.hasHeader("X-Page")
                    || response.hasHeader("Link")
                    || response.hasHeader("X-Pagination");
            boolean hasPaginationInBody = body.contains("\"total\"") || body.contains("\"page\"")
                    || body.contains("\"next\"") || body.contains("\"pagination\"")
                    || body.contains("\"cursor\"");

            // If large response with no pagination indicators, flag it
            if (body.length() > 100_000 && !hasPaginationHeaders && !hasPaginationInBody) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Missing Pagination on Collection Endpoint",
                        "The API collection endpoint returned a large response (" +
                        (body.length() / 1024) + " KB) without any pagination metadata. " +
                        "Unbounded collection endpoints can be used to exhaust server resources.",
                        Severity.LOW,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Implement pagination for all collection endpoints. Include pagination metadata " +
                        "(total count, current page, next/previous links) in responses. " +
                        "Set a reasonable default and maximum page size."
                );
                finding.setEvidence("Response size: " + body.length() + " bytes; no pagination headers or metadata found");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing missing pagination on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }
}
