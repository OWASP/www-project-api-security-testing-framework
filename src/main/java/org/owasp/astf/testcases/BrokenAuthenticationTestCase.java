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
 * Tests for API2:2023 Broken Authentication.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API2:2023</a>
 */
public class BrokenAuthenticationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(BrokenAuthenticationTestCase.class);

    private static final List<String> AUTH_PATH_PATTERNS = List.of(
            "login", "auth", "token", "signin", "oauth", "session"
    );

    // JWT with "none" algorithm - known attack payload
    private static final String NONE_ALG_JWT =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +  // {"alg":"none","typ":"JWT"}
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ" + // {"sub":"1234567890","name":"Admin","iat":1516239022}
            ".";  // empty signature

    @Override
    public String getId() {
        return "ASTF-API2-2023";
    }

    @Override
    public String getName() {
        return "Broken Authentication";
    }

    @Override
    public String getDescription() {
        return """
               Tests for authentication weaknesses such as weak passwords, improper \
               token validation, missing or inconsistent authentication checks, and \
               credential exposure in URLs.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        // Always check for credential leakage in URLs (applies to all endpoint types)
        findings.addAll(checkTokenInUrl(endpoint));

        if (isAuthEndpoint(endpoint)) {
            findings.addAll(testWeakAuthentication(endpoint, httpClient));
        } else {
            findings.addAll(testMissingAuthentication(endpoint, httpClient));
            findings.addAll(testJwtNoneAlgorithm(endpoint, httpClient));
        }

        return findings;
    }

    private boolean isAuthEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return AUTH_PATH_PATTERNS.stream().anyMatch(path::contains);
    }

    private List<Finding> testWeakAuthentication(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        // Common weak credentials to test
        List<Map<String, String>> weakCredentials = List.of(
                Map.of("username", "admin", "password", "admin"),
                Map.of("username", "admin", "password", "password"),
                Map.of("username", "admin", "password", "admin123"),
                Map.of("username", "test", "password", "test"),
                Map.of("username", "user", "password", "password")
        );

        String fullUrl = endpoint.getFullUrl();
        for (Map<String, String> creds : weakCredentials) {
            try {
                String body = String.format("{\"username\":\"%s\",\"password\":\"%s\"}",
                        creds.get("username"), creds.get("password"));
                HttpResponse response = httpClient.postWithStatus(fullUrl, Map.of(), "application/json", body);

                if (response.isSuccess()) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Weak Default Credentials Accepted",
                            String.format("The authentication endpoint accepted weak credentials: %s/%s",
                                    creds.get("username"), creds.get("password")),
                            Severity.CRITICAL,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Enforce strong password policies, remove default credentials, and implement account lockout after failed attempts."
                    );
                    finding.setRequestDetails("POST " + fullUrl + " with credentials: " + creds.get("username"));
                    finding.setResponseDetails("Status: " + response.getStatusCode());
                    findings.add(finding);
                    break; // One finding is enough
                }
            } catch (Exception e) {
                logger.debug("Error testing weak credentials on {}: {}", endpoint, e.getMessage());
            }
        }

        // Check for missing account lockout (no rate limiting or lockout after multiple attempts)
        if (findings.isEmpty()) {
            findings.add(new Finding(
                    UUID.randomUUID().toString(),
                    "Authentication Endpoint Requires Manual Review",
                    "Authentication endpoints should be carefully reviewed for weak credentials, " +
                    "account lockout mechanisms, rate limiting, and proper token validation.",
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Implement strong password policies, account lockout after failed attempts, " +
                    "rate limiting, and proper token generation using industry-standard algorithms."
            ));
        }

        return findings;
    }

    private List<Finding> testMissingAuthentication(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.isRequiresAuthentication()) {
            return findings;
        }

        try {
            String fullUrl = endpoint.getFullUrl();
            HttpResponse response = null;

            // Send request without any authentication headers
            Map<String, String> noAuthHeaders = Map.of();
            switch (endpoint.getMethod().toUpperCase()) {
                case "GET"    -> response = httpClient.getWithStatus(fullUrl, noAuthHeaders);
                case "POST"   -> response = httpClient.postWithStatus(fullUrl, noAuthHeaders, "application/json", "{}");
                case "PUT"    -> response = httpClient.putWithStatus(fullUrl, noAuthHeaders, "application/json", "{}");
                case "DELETE" -> response = httpClient.deleteWithStatus(fullUrl, noAuthHeaders);
                default -> {
                    // Fall back to string-based check for unsupported methods
                    String body = httpClient.get(fullUrl, noAuthHeaders);
                    if (body != null && !body.isEmpty()
                            && !body.contains("unauthorized")
                            && !body.contains("authentication")) {
                        findings.add(buildMissingAuthFinding(endpoint));
                    }
                    return findings;
                }
            }

            if (response != null && response.isSuccess()) {
                // A 2xx response without auth headers indicates missing authentication controls
                findings.add(buildMissingAuthFinding(endpoint));
            }
        } catch (Exception e) {
            logger.debug("Error testing missing authentication on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private Finding buildMissingAuthFinding(EndpointInfo endpoint) {
        return new Finding(
                UUID.randomUUID().toString(),
                "Missing Authentication Controls",
                "The API endpoint appears to be accessible without proper authentication.",
                Severity.HIGH,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Implement consistent authentication checks across all API endpoints that require them."
        );
    }

    private List<Finding> testJwtNoneAlgorithm(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.isRequiresAuthentication()) {
            return findings;
        }

        try {
            String fullUrl = endpoint.getFullUrl();
            Map<String, String> noneAlgHeaders = Map.of("Authorization", "Bearer " + NONE_ALG_JWT);
            // Use the endpoint's own method so mocks remain consistent in tests
            HttpResponse response = switch (endpoint.getMethod().toUpperCase()) {
                case "POST"   -> httpClient.postWithStatus(fullUrl, noneAlgHeaders, "application/json", "{}");
                case "PUT"    -> httpClient.putWithStatus(fullUrl, noneAlgHeaders, "application/json", "{}");
                case "DELETE" -> httpClient.deleteWithStatus(fullUrl, noneAlgHeaders);
                default       -> httpClient.getWithStatus(fullUrl, noneAlgHeaders);
            };

            if (response != null && response.isSuccess()) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "JWT 'none' Algorithm Accepted",
                        "The API accepted a JWT token with 'none' signing algorithm, which means " +
                        "tokens can be forged without a valid signature.",
                        Severity.CRITICAL,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Always validate JWT signatures. Reject tokens with 'none' or 'null' algorithm. " +
                        "Use a whitelist of accepted signing algorithms."
                );
                finding.setEvidence("Server returned HTTP " + response.getStatusCode() +
                        " when presented with a JWT using 'none' algorithm");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing JWT none algorithm on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private List<Finding> checkTokenInUrl(EndpointInfo endpoint) {
        List<Finding> findings = new ArrayList<>();
        String path = endpoint.getPath().toLowerCase();

        // Check if the URL path contains patterns suggesting token/credential leakage
        List<String> tokenPatterns = List.of("token=", "api_key=", "apikey=", "access_token=",
                "auth=", "password=", "secret=");

        for (String pattern : tokenPatterns) {
            if (path.contains(pattern)) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Sensitive Token Exposed in URL",
                        "Authentication token or credentials appear to be passed in the URL, " +
                        "which can be captured in server logs, browser history, and proxy caches.",
                        Severity.HIGH,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Pass authentication tokens in the Authorization header or request body, never in URLs."
                );
                finding.setEvidence("Pattern '" + pattern + "' found in endpoint path: " + endpoint.getPath());
                findings.add(finding);
                break;
            }
        }

        return findings;
    }
}
