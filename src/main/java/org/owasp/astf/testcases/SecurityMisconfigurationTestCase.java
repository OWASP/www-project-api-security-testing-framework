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
 * Tests for API8:2023 Security Misconfiguration.
 *
 * Security misconfiguration covers a wide range of issues including missing security headers,
 * overly permissive CORS, exposed debug endpoints, unnecessary HTTP methods, and verbose error
 * messages that reveal sensitive implementation details.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/">OWASP API8:2023</a>
 */
public class SecurityMisconfigurationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(SecurityMisconfigurationTestCase.class);

    private static final List<String> REQUIRED_SECURITY_HEADERS = List.of(
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-XSS-Protection"
    );

    private static final List<String> DEBUG_ENDPOINTS = List.of(
            "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
            "/actuator/mappings", "/actuator/metrics", "/actuator/info",
            "/.env", "/debug", "/debug/vars", "/_debug",
            "/info", "/health", "/status", "/ping",
            "/swagger-ui.html", "/swagger-ui/", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml", "/api-docs",
            "/console", "/h2-console", "/phpinfo.php",
            "/__debug__", "/server-status", "/server-info",
            "/trace", "/dump", "/heapdump", "/threaddump"
    );

    private static final List<String> ERROR_SENSITIVE_PATTERNS = List.of(
            "stack trace", "stacktrace", "at org.", "at java.", "at com.",
            "exception", "NullPointerException", "SQLException",
            "org.springframework", "hibernate", "datasource",
            "internal server error at", "caused by:",
            "password", "secret", "token", "key", "credential"
    );

    @Override
    public String getId() {
        return "ASTF-API8-2023";
    }

    @Override
    public String getName() {
        return "Security Misconfiguration";
    }

    @Override
    public String getDescription() {
        return "Tests for missing security headers, overly permissive CORS policies, exposed debug " +
               "endpoints, verbose error messages, and other common security misconfigurations.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testMissingSecurityHeaders(endpoint, httpClient));
        findings.addAll(testCorsMisconfiguration(endpoint, httpClient));
        findings.addAll(testDebugEndpoints(endpoint, httpClient));
        findings.addAll(testVerboseErrors(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testMissingSecurityHeaders(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        try {
            HttpResponse response = httpClient.getWithStatus(endpoint.getFullUrl(), Map.of());
            if (response == null || response.isNotFound()) return findings;

            List<String> missingHeaders = new ArrayList<>();
            for (String header : REQUIRED_SECURITY_HEADERS) {
                if (!response.hasHeader(header)) {
                    missingHeaders.add(header);
                }
            }

            if (!missingHeaders.isEmpty()) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Missing Security Response Headers",
                        "The API response is missing important security headers: " +
                        String.join(", ", missingHeaders) + ". These headers protect against " +
                        "common web vulnerabilities including clickjacking, MIME sniffing, and XSS.",
                        missingHeaders.size() >= 3 ? Severity.MEDIUM : Severity.LOW,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Add the following security headers to all API responses: " +
                        "X-Content-Type-Options: nosniff, X-Frame-Options: DENY, " +
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains, " +
                        "Content-Security-Policy: default-src 'self'."
                );
                finding.setEvidence("Missing headers: " + String.join(", ", missingHeaders));
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing security headers on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private List<Finding> testCorsMisconfiguration(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        try {
            // Send a request with a suspicious Origin header to test CORS policy
            Map<String, String> corsHeaders = Map.of(
                    "Origin", "https://evil-attacker.com",
                    "Access-Control-Request-Method", "GET"
            );

            HttpResponse response = httpClient.getWithStatus(endpoint.getFullUrl(), corsHeaders);
            if (response == null) return findings;

            String allowOrigin = response.getHeader("Access-Control-Allow-Origin");
            String allowCredentials = response.getHeader("Access-Control-Allow-Credentials");

            if ("*".equals(allowOrigin)) {
                findings.add(new Finding(
                        UUID.randomUUID().toString(),
                        "Wildcard CORS Policy",
                        "The API uses a wildcard (*) Access-Control-Allow-Origin policy, allowing any " +
                        "website to make cross-origin requests. This may expose sensitive data to " +
                        "malicious websites.",
                        Severity.MEDIUM,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Restrict CORS to specific trusted origins. Never combine wildcard CORS with " +
                        "Access-Control-Allow-Credentials: true. Use an origin allowlist."
                ));
            } else if ("https://evil-attacker.com".equals(allowOrigin)) {
                // The server reflected back the attacker's origin
                String severity = "true".equalsIgnoreCase(allowCredentials) ? "CRITICAL" : "HIGH";
                findings.add(new Finding(
                        UUID.randomUUID().toString(),
                        "Overly Permissive CORS - Arbitrary Origin Reflected",
                        "The API reflects any provided Origin header in the Access-Control-Allow-Origin " +
                        "response header" + ("true".equalsIgnoreCase(allowCredentials)
                                ? " AND allows credentials, enabling session hijacking attacks" : "") + ".",
                        "true".equalsIgnoreCase(allowCredentials) ? Severity.CRITICAL : Severity.HIGH,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Validate the Origin header against an allowlist of trusted origins. " +
                        "Never reflect arbitrary origins. Do not allow credentials with permissive CORS."
                ));
            }
        } catch (Exception e) {
            logger.debug("Error testing CORS on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private List<Finding> testDebugEndpoints(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = endpoint.getBaseUrl();

        if (baseUrl == null || baseUrl.isEmpty()) return findings;

        // Only run debug endpoint discovery once per base URL (check by path being root)
        if (!endpoint.getPath().equals("/") && !endpoint.getPath().isEmpty()) return findings;

        String cleanBase = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String debugPath : DEBUG_ENDPOINTS) {
            String testUrl = cleanBase + debugPath;
            try {
                HttpResponse response = httpClient.getWithStatus(testUrl, Map.of());

                if (response != null && response.isSuccess()
                        && !response.getBody().isEmpty()) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Debug/Diagnostic Endpoint Exposed",
                            String.format("The debug or diagnostic endpoint '%s' is publicly accessible " +
                                    "and returned a non-empty response. Debug endpoints can expose sensitive " +
                                    "configuration, environment variables, internal routes, and system internals.",
                                    debugPath),
                            Severity.HIGH,
                            getId(),
                            "GET " + debugPath,
                            "Disable or restrict access to debug endpoints in production environments. " +
                            "If these endpoints are required, protect them with authentication and restrict " +
                            "access to internal networks or VPN only."
                    );
                    finding.setRequestDetails("GET " + testUrl);
                    finding.setResponseDetails("HTTP " + response.getStatusCode() +
                            "; body length: " + response.getBody().length());
                    findings.add(finding);
                }
            } catch (Exception e) {
                logger.debug("Error testing debug endpoint {}: {}", testUrl, e.getMessage());
            }
        }

        return findings;
    }

    private List<Finding> testVerboseErrors(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        // Trigger potential error by sending a malformed request
        List<String> malformedPayloads = List.of(
                "not-json{{{",
                "{\"id\": \"not-a-number\", \"data\": null}",
                "' OR '1'='1",
                "<script>alert(1)</script>"
        );

        for (String payload : malformedPayloads) {
            try {
                HttpResponse response = endpoint.getMethod().equalsIgnoreCase("GET")
                        ? httpClient.getWithStatus(endpoint.getFullUrl() + "?q=" + urlEncode(payload), Map.of())
                        : httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", payload);

                if (response != null && response.isServerError()) {
                    String body = response.getBody().toLowerCase();
                    List<String> foundPatterns = new ArrayList<>();

                    for (String pattern : ERROR_SENSITIVE_PATTERNS) {
                        if (body.contains(pattern.toLowerCase())) {
                            foundPatterns.add(pattern);
                        }
                    }

                    if (!foundPatterns.isEmpty()) {
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "Verbose Error Messages Exposing Sensitive Information",
                                "The API returns verbose error messages containing sensitive implementation " +
                                "details: " + String.join(", ", foundPatterns) + ". This information " +
                                "aids attackers in understanding the application internals.",
                                Severity.MEDIUM,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Implement custom error handling that returns generic error messages to clients. " +
                                "Log detailed error information server-side only. Never expose stack traces, " +
                                "internal paths, framework names, or database details in API responses."
                        );
                        finding.setEvidence("Error patterns found: " + String.join(", ", foundPatterns));
                        findings.add(finding);
                        break;
                    }
                }
            } catch (Exception e) {
                logger.debug("Error testing verbose errors on {}: {}", endpoint, e.getMessage());
            }
        }

        return findings;
    }

    private String urlEncode(String value) {
        return value.replace("&", "%26").replace("=", "%3D").replace("+", "%2B")
                .replace(" ", "%20").replace("<", "%3C").replace(">", "%3E")
                .replace("'", "%27").replace("\"", "%22");
    }
}
