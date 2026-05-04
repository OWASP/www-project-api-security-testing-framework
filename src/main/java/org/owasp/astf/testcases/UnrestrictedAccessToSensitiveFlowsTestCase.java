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
        String path = endpoint.getPath().toLowerCase();
        return SENSITIVE_FLOW_PATTERNS.stream().anyMatch(path::contains);
    }

    private List<Finding> testAutomatedAbuse(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        int successCount = 0;
        int rateLimitedCount = 0;
        String body = endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}";

        for (int i = 0; i < FLOW_ABUSE_THRESHOLD; i++) {
            try {
                HttpResponse response = httpClient.postWithStatus(
                        endpoint.getFullUrl(), Map.of(), "application/json", body);

                if (response != null) {
                    if (response.isRateLimited()) {
                        rateLimitedCount++;
                        break;
                    } else if (response.isSuccess() || response.getStatusCode() == 422) {
                        // 422 Unprocessable Entity still counts — request reached the business layer
                        successCount++;
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
        }

        return findings;
    }

    private List<Finding> testMissingBotProtection(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        // Check if the endpoint has any bot protection indicators in the first response
        try {
            HttpResponse response = endpoint.getMethod().equalsIgnoreCase("POST")
                    ? httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", "{}")
                    : httpClient.getWithStatus(endpoint.getFullUrl(), Map.of());

            if (response == null) return findings;

            boolean hasCaptchaChallenge = response.getBody().toLowerCase().contains("captcha")
                    || response.getBody().toLowerCase().contains("recaptcha")
                    || response.getBody().toLowerCase().contains("challenge");
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
