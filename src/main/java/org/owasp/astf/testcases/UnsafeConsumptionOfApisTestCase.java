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
 * Tests for API10:2023 Unsafe Consumption of APIs.
 *
 * Developers tend to trust data received from third-party APIs more than user input.
 * APIs that pass third-party data through without validation, or that redirect to
 * untrusted third-party URLs, can be exploited as vectors for injection attacks.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/">OWASP API10:2023</a>
 */
public class UnsafeConsumptionOfApisTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(UnsafeConsumptionOfApisTestCase.class);

    // Patterns suggesting the API integrates with or proxies third-party services
    private static final List<String> INTEGRATION_PATH_PATTERNS = List.of(
            "webhook", "proxy", "integration", "external", "third-party", "thirdparty",
            "import", "export", "sync", "feed", "aggregate", "forward", "relay",
            "partner", "vendor", "provider", "service"
    );

    // Injection payloads to test if third-party data is validated
    private static final List<String> INJECTION_PAYLOADS = List.of(
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "{{7*7}}",                  // Template injection
            "${7*7}",                   // EL injection
            "../../../etc/passwd",      // Path traversal
            "%00null",                  // Null byte injection
            "\\x00",                    // Null byte (hex)
            "admin'/*",                 // SQL comment injection
            "\r\nX-Injected-Header: value" // HTTP header injection
    );

    // Patterns that indicate successful injection in responses
    private static final List<String> INJECTION_SUCCESS_PATTERNS = List.of(
            "<script>",               // Unescaped XSS
            "alert('xss')",           // XSS executed context
            "49",                     // 7*7=49 template injection
            "root:x:0:0",            // /etc/passwd content
            "X-Injected-Header",     // Header injection reflected
            "sql", "syntax error", "mysql", "sqlite", "postgresql" // SQL errors
    );

    @Override
    public String getId() {
        return "ASTF-API10-2023";
    }

    @Override
    public String getName() {
        return "Unsafe Consumption of APIs";
    }

    @Override
    public String getDescription() {
        return "Tests for insufficient validation of data consumed from third-party APIs, " +
               "including injection vulnerabilities and unsafe redirect behaviors in API integrations.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testInjectionViaIntegrationEndpoints(endpoint, httpClient));
        findings.addAll(testOpenRedirect(endpoint, httpClient));
        findings.addAll(checkTlsForExternalCalls(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testInjectionViaIntegrationEndpoints(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!isIntegrationEndpoint(endpoint)) {
            return findings;
        }

        String method = endpoint.getMethod().toUpperCase();

        for (String payload : INJECTION_PAYLOADS) {
            try {
                HttpResponse response;
                if (method.equals("GET")) {
                    String testUrl = endpoint.getFullUrl() + "?data=" + urlEncode(payload)
                            + "&query=" + urlEncode(payload);
                    response = httpClient.getWithStatus(testUrl, Map.of());
                } else {
                    String body = String.format(
                            "{\"data\":\"%s\",\"value\":\"%s\",\"query\":\"%s\"}",
                            escapeJson(payload), escapeJson(payload), escapeJson(payload));
                    response = switch (method) {
                        case "POST"  -> httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                        case "PUT"   -> httpClient.putWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                        case "PATCH" -> httpClient.patchWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                        default      -> null;
                    };
                }

                if (response != null && response.isSuccess()) {
                    String responseBody = response.getBody();
                    for (String pattern : INJECTION_SUCCESS_PATTERNS) {
                        if (responseBody.toLowerCase().contains(pattern.toLowerCase())
                                && !pattern.equals("49")) { // Skip false positives for "49"
                            Finding finding = new Finding(
                                    UUID.randomUUID().toString(),
                                    "Injection Vulnerability in API Integration Endpoint",
                                    String.format("The API integration endpoint at '%s' appears to reflect " +
                                            "unvalidated input back in the response. This may indicate " +
                                            "that data from third-party API calls is not properly validated " +
                                            "before being used or returned. Detected pattern: '%s'.",
                                            endpoint.getPath(), pattern),
                                    Severity.HIGH,
                                    getId(),
                                    endpoint.getMethod() + " " + endpoint.getPath(),
                                    "Treat all data from third-party APIs as untrusted user input. " +
                                    "Validate and sanitize all externally-sourced data before using it. " +
                                    "Implement output encoding appropriate to the context. " +
                                    "Use parameterized queries for any database operations using external data."
                            );
                            finding.setEvidence("Payload: " + payload + "\nPattern found: " + pattern);
                            findings.add(finding);
                            return findings; // One injection finding is enough
                        }
                    }
                }
            } catch (Exception e) {
                logger.debug("Error testing injection on {}: {}", endpoint, e.getMessage());
            }
        }

        return findings;
    }

    private List<Finding> testOpenRedirect(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        List<String> redirectParams = List.of("redirect", "return", "returnUrl", "return_url",
                "next", "continue", "url", "goto", "back");
        String maliciousUrl = "https://evil-attacker.example.com/phishing";

        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        for (String param : redirectParams) {
            String testUrl = endpoint.getFullUrl()
                    + (endpoint.getFullUrl().contains("?") ? "&" : "?")
                    + param + "=" + urlEncode(maliciousUrl);

            try {
                HttpResponse response = httpClient.getWithStatus(testUrl, Map.of());

                if (response != null && response.isRedirect()) {
                    String location = response.getHeader("Location");
                    if (location != null && location.contains("evil-attacker.example.com")) {
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "Open Redirect Vulnerability",
                                String.format("The endpoint redirects to an attacker-controlled URL when " +
                                        "the '%s' parameter is set to an external URL. This can be exploited " +
                                        "for phishing attacks by crafting trusted-looking URLs.", param),
                                Severity.MEDIUM,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Validate redirect URLs against an allowlist of trusted domains. " +
                                "Reject or ignore redirect parameters pointing to external domains. " +
                                "Use relative paths for redirects where possible."
                        );
                        finding.setRequestDetails("GET " + testUrl);
                        finding.setEvidence("Location header: " + location);
                        findings.add(finding);
                        break;
                    }
                }
            } catch (Exception e) {
                logger.debug("Error testing open redirect on {}: {}", endpoint, e.getMessage());
            }
        }

        return findings;
    }

    private List<Finding> checkTlsForExternalCalls(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!isIntegrationEndpoint(endpoint)) return findings;

        // Check if the API accepts HTTP (non-TLS) callback/webhook URLs
        List<String> httpCallbackParams = List.of("webhookUrl", "webhook_url", "callbackUrl", "callback_url");
        String httpPayload = "http://example.com/callback";

        if (!endpoint.getMethod().equals("POST") && !endpoint.getMethod().equals("PUT")) {
            return findings;
        }

        for (String param : httpCallbackParams) {
            String body = String.format("{\"%s\":\"%s\"}", param, httpPayload);
            try {
                HttpResponse response = endpoint.getMethod().equals("POST")
                        ? httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body)
                        : httpClient.putWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);

                if (response != null && (response.isSuccess() || response.getStatusCode() == 201)) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Insecure HTTP Webhook/Callback URL Accepted",
                            String.format("The API accepted an HTTP (non-TLS) webhook/callback URL via the " +
                                    "'%s' parameter. Webhooks over plain HTTP expose sensitive data to " +
                                    "network eavesdropping and man-in-the-middle attacks.", param),
                            Severity.MEDIUM,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Require all webhook and callback URLs to use HTTPS. " +
                            "Validate that URLs use TLS before accepting them. " +
                            "Implement webhook signature verification to ensure payload integrity."
                    );
                    finding.setEvidence("HTTP webhook URL accepted: " + httpPayload);
                    findings.add(finding);
                    break;
                }
            } catch (Exception e) {
                logger.debug("Error testing TLS for external calls on {}: {}", endpoint, e.getMessage());
            }
        }

        return findings;
    }

    private boolean isIntegrationEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return INTEGRATION_PATH_PATTERNS.stream().anyMatch(path::contains);
    }

    private String urlEncode(String value) {
        return value.replace(":", "%3A").replace("/", "%2F").replace("?", "%3F")
                .replace("=", "%3D").replace("&", "%26").replace(" ", "%20")
                .replace("<", "%3C").replace(">", "%3E").replace("'", "%27")
                .replace("\"", "%22").replace("\r", "%0D").replace("\n", "%0A");
    }

    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
}
