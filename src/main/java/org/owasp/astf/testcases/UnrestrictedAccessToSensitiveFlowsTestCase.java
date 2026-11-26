package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
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
 * Tests for API6:2023 Unrestricted Access to Sensitive Business Flows.
 *
 * APIs that expose business flows without considering how they could be used against the
 * application's business model are vulnerable. Attackers can abuse these flows through
 * automation to negatively impact the business (e.g., mass buying, OTP flooding, account creation).
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/">OWASP API6:2023</a>
 */
public class UnrestrictedAccessToSensitiveFlowsTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(UnrestrictedAccessToSensitiveFlowsTestCase.class);

    private static final List<String> SENSITIVE_FLOW_PATTERNS = List.of(
            "checkout", "purchase", "buy", "order", "payment", "pay",
            "register", "signup", "sign-up", "sign_up", "enroll",
            "transfer", "withdraw", "deposit",
            "vote", "like", "review", "rate",
            "invite", "refer", "share",
            "otp", "verify", "verification", "confirm"
    );

    private static final int FLOW_ABUSE_THRESHOLD = 10; // Requests before rate limiting expected
    // Same body-level throttle phrases as UnrestrictedResourceConsumptionTestCase — docs promise
    // these markers for login/reset flows, and some APIs signal rejection via a 200 body message.
    private static final List<String> THROTTLE_BODY_MARKERS = List.of(
            "quota exceeded", "rate limit exceeded", "too many requests", "throttled", "slow down"
    );

    @Override
    public String getId() {
        return "ASTF-API6-2023";
    }

    @Override
    public String getName() {
        return "Unrestricted Access to Sensitive Business Flows";
    }

    @Override
    public String getDescription() {
        return "Tests for APIs that allow automated abuse of critical business flows such as " +
               "purchasing, registration, voting, or financial transactions without sufficient " +
               "bot protection or rate limiting.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        if (!isSensitiveBusinessFlow(endpoint)) {
            return findings;
        }

        findings.addAll(testAutomatedAbuse(endpoint, httpClient));
        findings.addAll(testMissingBotProtection(endpoint, httpClient));

        return findings;
    }

    private boolean isSensitiveBusinessFlow(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase(Locale.ROOT);
        return SENSITIVE_FLOW_PATTERNS.stream().anyMatch(path::contains);
    }

    private List<Finding> testAutomatedAbuse(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        int successCount = 0;
        int rateLimitedCount = 0;
        int rejectedInvalidCount = 0;
        String body = endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}";

        for (int i = 0; i < FLOW_ABUSE_THRESHOLD; i++) {
            try {
                HttpResponse response = httpClient.postWithStatus(
                        endpoint.getFullUrl(), Map.of(), "application/json", body);

                if (response != null) {
                    if (isThrottleSignal(response)) {
                        rateLimitedCount++;
                        break;
                    } else if (response.isSuccess()) {
                        successCount++;
                    } else if (isClientRejection(response.getStatusCode())) {
                        // 4xx (other than 429/423) means the request never reached an accepted
                        // business-flow outcome — not evidence the flow can be abused.
                        rejectedInvalidCount++;
                    }
                }
            } catch (Exception e) {
                logger.debug("Error during business flow abuse test on {}: {}", endpoint, e.getMessage());
                break;
            }
        }

        if (successCount >= FLOW_ABUSE_THRESHOLD && rateLimitedCount == 0) {
            Finding finding = new Finding(
                    UUID.randomUUID().toString(),
                    "Sensitive Business Flow Accessible Without Rate Limiting",
                    String.format("The sensitive business flow endpoint accepted %d consecutive automated " +
                            "requests without triggering rate limiting or bot detection. This enables " +
                            "automated abuse such as mass account creation, bulk purchasing, or OTP flooding.",
                            successCount),
                    Severity.HIGH,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Implement rate limiting, CAPTCHA or other bot detection mechanisms on sensitive " +
                    "business flow endpoints. Use device fingerprinting and behavioral analysis to " +
                    "detect and block automated abuse. Implement business logic validation limits " +
                    "(e.g., max orders per account per day)."
            );
            finding.setEvidence(successCount + " automated requests succeeded without triggering protections");
            findings.add(finding);
        } else if (rateLimitedCount == 0 && successCount + rejectedInvalidCount >= FLOW_ABUSE_THRESHOLD) {
            // Rejected attempts with a real sample body can be failed guesses (wrong OTP, coupon,
            // password) that are never throttled; with the {} placeholder they are only missing fields.
            boolean realBodySupplied = endpoint.getRequestBody() != null
                    && !endpoint.getRequestBody().isBlank() && !endpoint.getRequestBody().trim().equals("{}");
            Finding finding;
            if (successCount > 0 || realBodySupplied) {
                finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Sensitive Business Flow Not Throttled (attempts rejected, never limited)",
                        String.format("The sensitive business flow endpoint answered %d consecutive automated " +
                                "requests without any throttling signal: %d were accepted and %d were rejected " +
                                "with HTTP 4xx. If the rejections are failed guesses (for example a wrong OTP or " +
                                "coupon code), an attacker can keep guessing without limit.",
                                successCount + rejectedInvalidCount, successCount, rejectedInvalidCount),
                        Severity.MEDIUM,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Throttle or lock out repeated attempts on sensitive flows, counting failed attempts, " +
                        "not only successful ones."
                );
            } else {
                finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Sensitive Business Flow Rate Limiting Inconclusive (all attempts rejected as invalid)",
                        String.format("The sensitive business flow endpoint rejected all %d automated attempts " +
                                "with HTTP 4xx (other than 429/423). ASTF had no sample request body for this " +
                                "endpoint and sent {}, so the rejections are most likely missing-field validation " +
                                "errors, which say nothing about whether the flow can be abused. Provide a valid " +
                                "sample body via the config endpoints requestBody field and re-scan.",
                                rejectedInvalidCount),
                        Severity.INFO,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Supply a realistic requestBody for this endpoint in the scan configuration so the " +
                        "abuse/rate-limit check can exercise the accepted business path."
                );
            }
            finding.setEvidence(successCount + " accepted (2xx), " + rejectedInvalidCount +
                    " rejected (4xx), 0 throttled; request body: " + (realBodySupplied ? "configured sample" : "{} placeholder"));
            findings.add(finding);
        }

        return findings;
    }

    private boolean isThrottleSignal(HttpResponse response) {
        return response.isRateLimited()
                || response.getStatusCode() == 423
                || bodyIndicatesRateLimited(response.getBody());
    }

    /** 4xx other than throttling (429/423) and other than "path not served" (404/405/410). */
    private boolean isClientRejection(int statusCode) {
        return statusCode >= 400 && statusCode < 500
                && statusCode != 429 && statusCode != 423
                && statusCode != 404 && statusCode != 405 && statusCode != 410;
    }

    private boolean bodyIndicatesRateLimited(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        String lower = body.toLowerCase(Locale.ROOT);
        return THROTTLE_BODY_MARKERS.stream().anyMatch(lower::contains);
    }

    private List<Finding> testMissingBotProtection(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        // Check if the endpoint has any bot protection indicators in the first response
        try {
            HttpResponse response = endpoint.getMethod().equalsIgnoreCase("POST")
                    ? httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", "{}")
                    : httpClient.getWithStatus(endpoint.getFullUrl(), Map.of());

            if (response == null) return findings;

            boolean hasCaptchaChallenge = response.getBody().toLowerCase(Locale.ROOT).contains("captcha")
                    || response.getBody().toLowerCase(Locale.ROOT).contains("recaptcha")
                    || response.getBody().toLowerCase(Locale.ROOT).contains("challenge");
            boolean hasRateLimitHeaders = response.hasHeader("X-RateLimit-Limit")
                    || response.hasHeader("X-Rate-Limit")
                    || response.hasHeader("RateLimit-Limit")
                    || response.hasHeader("Retry-After");

            if (response.isSuccess() && !hasCaptchaChallenge && !hasRateLimitHeaders) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Sensitive Business Flow Missing Bot Protection Headers",
                        "The sensitive business flow endpoint does not return rate limiting headers " +
                        "(X-RateLimit-Limit, Retry-After) or CAPTCHA challenges, suggesting bot " +
                        "protection may not be implemented.",
                        Severity.MEDIUM,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Add rate limiting response headers (X-RateLimit-Limit, X-RateLimit-Remaining, " +
                        "Retry-After) to inform clients of limits. Implement CAPTCHA or other bot " +
                        "detection for critical business flows."
                );
                finding.setEvidence("No rate limiting headers or CAPTCHA indicators found in response to: " +
                        endpoint.getMethod() + " " + endpoint.getPath());
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing bot protection on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }
}
