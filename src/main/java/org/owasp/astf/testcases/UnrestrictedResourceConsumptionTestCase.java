package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
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

    // A 2xx status alone doesn't prove the request was genuinely accepted — some APIs return
    // 200 with an explicit rate-limit/quota rejection message in the body instead of a 429/4xx
    // status. These phrases are specific enough that they're unlikely to appear in an unrelated
    // healthy response.
    private static final List<String> FAILURE_BODY_MARKERS = List.of(
            "quota exceeded", "rate limit exceeded", "too many requests", "throttled", "slow down"
    );

    // Headers that proxies and frameworks commonly read the client address from. A limiter that
    // trusts any of them from the client can be reset by changing the value on each request.
    static final List<String> CLIENT_IP_HEADERS = List.of(
            "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP", "X-Originating-IP"
    );
    private static final int SPOOFED_IP_REQUESTS = 5;
    private static final int SPOOFED_IP_SUCCESS_THRESHOLD = 4;

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
                    if (response.isRateLimited() || bodyIndicatesRateLimited(response.getBody())) {
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

        if (rateLimitedCount > 0) {
            Finding bypass = testRateLimitBypassViaClientIpHeaders(endpoint, fullUrl, httpClient);
            if (bypass != null) {
                findings.add(bypass);
            }
        }

        return findings;
    }

    /**
     * Runs right after the burst above was rate limited. A limiter keyed on a client-IP header
     * that the client controls is no limiter: each request can claim a new address. Sends a plain
     * control request (it must still be limited, otherwise the window has already reset and
     * nothing can be concluded), then {@link #SPOOFED_IP_REQUESTS} requests that each carry a
     * different address from the TEST-NET-3 documentation range in every common client-IP header,
     * then a second plain control. Reported only if both controls are still limited and at least
     * {@link #SPOOFED_IP_SUCCESS_THRESHOLD} spoofed requests were accepted.
     *
     * @return a finding when the limit is bypassed, or null
     */
    Finding testRateLimitBypassViaClientIpHeaders(EndpointInfo endpoint, String fullUrl, HttpClient httpClient) {
        try {
            if (!isLimited(httpClient.getWithStatus(fullUrl, Map.of()))) {
                return null;
            }
            int accepted = 0;
            HttpResponse lastAccepted = null;
            for (int i = 0; i < SPOOFED_IP_REQUESTS; i++) {
                String ip = "203.0.113." + (10 + i);
                Map<String, String> headers = new LinkedHashMap<>();
                for (String header : CLIENT_IP_HEADERS) {
                    headers.put(header, ip);
                }
                HttpResponse response = httpClient.getWithStatus(fullUrl, headers);
                if (response != null && response.isSuccess() && !isLimited(response)) {
                    accepted++;
                    lastAccepted = response;
                }
            }
            if (accepted < SPOOFED_IP_SUCCESS_THRESHOLD
                    || !isLimited(httpClient.getWithStatus(fullUrl, Map.of()))) {
                return null;
            }
            Finding finding = new Finding(
                    UUID.randomUUID().toString(),
                    "Rate Limiting Bypassed With Spoofed Client-IP Headers",
                    String.format("The endpoint rate limited a burst of requests, and stayed limited for " +
                            "requests without extra headers, but accepted %d of %d requests that each claimed " +
                            "a different client address in %s. The limiter trusts headers the client sets, " +
                            "so anyone can reset it on every request.",
                            accepted, SPOOFED_IP_REQUESTS, String.join(", ", CLIENT_IP_HEADERS)),
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Key rate limits on the authenticated identity or on the connection's peer address. Only " +
                    "read X-Forwarded-For and similar headers when the request came through a proxy you " +
                    "control, and then only the entry that proxy added."
            );
            finding.setRequestDetails("GET " + fullUrl + "\n" + String.join(": 203.0.113.N\n", CLIENT_IP_HEADERS)
                    + ": 203.0.113.N (N = 10.." + (10 + SPOOFED_IP_REQUESTS - 1) + ")");
            finding.setEvidence("Plain requests before and after: rate limited\nSpoofed-address requests accepted: "
                    + accepted + "/" + SPOOFED_IP_REQUESTS + "\nLast accepted: HTTP " + lastAccepted.getStatusCode());
            return finding;
        } catch (Exception e) {
            logger.debug("Error testing rate-limit bypass on {}: {}", endpoint, e.getMessage());
            return null;
        }
    }

    private boolean isLimited(HttpResponse response) {
        return response != null && (response.isRateLimited() || bodyIndicatesRateLimited(response.getBody()));
    }

    private boolean looksLikeJsonData(String body) {
        if (body == null) {
            return false;
        }
        String trimmed = body.stripLeading();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    private boolean bodyIndicatesRateLimited(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        String lower = body.toLowerCase();
        return FAILURE_BODY_MARKERS.stream().anyMatch(lower::contains);
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
                    // A response body larger than 1MB suggests unbounded data return — but only
                    // when it's actually JSON/array data. A large non-JSON body (e.g. a default
                    // server error page, or an HTML page for an unrecognized query param) is not
                    // evidence of a missing pagination limit.
                    if (body.length() > 1_000_000 && looksLikeJsonData(body)) {
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

            // If large response with no pagination indicators, flag it — again, only when the
            // body is actually JSON data, to avoid miscounting a large non-API HTML page.
            if (body.length() > 100_000 && looksLikeJsonData(body) && !hasPaginationHeaders && !hasPaginationInBody) {
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
