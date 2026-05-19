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
 * Tests for API5:2023 Broken Function Level Authorization.
 *
 * APIs with complex access control policies (multiple groups, roles, hierarchies) tend to
 * have authorization issues. Attackers can exploit these by accessing administrative
 * endpoints without authorization, using different HTTP methods to bypass restrictions,
 * or accessing endpoints by guessing their paths.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/">OWASP API5:2023</a>
 */
public class BrokenFunctionLevelAuthorizationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(BrokenFunctionLevelAuthorizationTestCase.class);

    private static final List<String> ADMIN_PATH_PATTERNS = List.of(
            "/admin", "/administrator", "/manage", "/management", "/dashboard",
            "/superuser", "/root", "/internal", "/private", "/restricted",
            "/console", "/control", "/config", "/configuration", "/settings",
            "/system", "/ops", "/operations", "/backstage", "/staff", "/moderator"
    );

    private static final List<String> SENSITIVE_HTTP_METHODS = List.of("PUT", "DELETE", "PATCH");

    @Override
    public String getId() {
        return "ASTF-API5-2023";
    }

    @Override
    public String getName() {
        return "Broken Function Level Authorization";
    }

    @Override
    public String getDescription() {
        return "Tests for unauthorized access to administrative endpoints, HTTP method manipulation, " +
               "and access to privileged functions by regular or unauthenticated users.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testAdminEndpointAccess(endpoint, httpClient));
        findings.addAll(testHttpMethodEscalation(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testAdminEndpointAccess(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = endpoint.getBaseUrl();

        if (baseUrl == null || baseUrl.isEmpty()) {
            return findings;
        }

        String cleanBase = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String adminPath : ADMIN_PATH_PATTERNS) {
            String testUrl = cleanBase + adminPath;
            try {
                HttpResponse response = httpClient.getWithStatus(testUrl, Map.of());

                if (response != null && response.isSuccess() && isApiResponse(response)) {
                    // Only flag when the response looks like a real API/admin response (JSON/XML).
                    // SPAs and web frameworks return HTTP 200 with text/html for every unknown
                    // path (client-side routing fallback) — those are false positives.
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Administrative Endpoint Accessible Without Authorization",
                            String.format("The administrative endpoint '%s' returned HTTP %d without " +
                                    "requiring authentication or elevated privileges. This could allow " +
                                    "unauthorized access to management functionality.",
                                    adminPath, response.getStatusCode()),
                            Severity.CRITICAL,
                            getId(),
                            "GET " + adminPath,
                            "Restrict access to administrative endpoints using role-based access control. " +
                            "Ensure admin endpoints require authentication and appropriate privilege levels. " +
                            "Consider placing admin interfaces on a separate network or VPN."
                    );
                    finding.setRequestDetails("GET " + testUrl);
                    finding.setResponseDetails("HTTP " + response.getStatusCode() +
                            "; body length: " + response.getBody().length());
                    findings.add(finding);
                }
            } catch (Exception e) {
                logger.debug("Error testing admin endpoint {}: {}", testUrl, e.getMessage());
            }
        }

        return findings;
    }

    /**
     * Returns true when the response looks like a real API/service response rather than
     * an HTML page.  SPAs and reverse proxies typically return HTTP 200 with text/html
     * for every unknown path (client-side routing fallback), which would otherwise
     * produce false positives for admin-path probing and method-escalation checks.
     *
     * <p>A response is considered an API response when:
     * <ul>
     *   <li>the Content-Type header contains "json", "xml", or "plain" (structured data), OR</li>
     *   <li>no Content-Type header is present (raw API response), OR</li>
     *   <li>the body starts with '{' or '[' (JSON) regardless of Content-Type</li>
     * </ul>
     */
    private boolean isApiResponse(HttpResponse response) {
        // Check Content-Type header first
        String contentType = response.getHeaders().entrySet().stream()
                .filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("Content-Type"))
                .flatMap(e -> e.getValue().stream())
                .findFirst()
                .orElse("")
                .toLowerCase();

        if (!contentType.isEmpty()) {
            // Explicit HTML → SPA fallback, skip
            if (contentType.contains("text/html")) {
                return false;
            }
            // JSON, XML, plain text → real API response
            if (contentType.contains("json") || contentType.contains("xml") || contentType.contains("text/plain")) {
                return true;
            }
        }

        // No Content-Type or unrecognised type — fall back to body sniffing
        String body = response.getBody();
        if (body != null) {
            String trimmed = body.stripLeading();
            return trimmed.startsWith("{") || trimmed.startsWith("[");
        }

        return false;
    }

    private List<Finding> testHttpMethodEscalation(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        // Only test GET endpoints for method escalation
        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        String fullUrl = endpoint.getFullUrl();

        for (String method : SENSITIVE_HTTP_METHODS) {
            try {
                HttpResponse getResponse  = httpClient.getWithStatus(fullUrl, Map.of());
                HttpResponse testResponse = switch (method) {
                    case "PUT"    -> httpClient.putWithStatus(fullUrl, Map.of(), "application/json", "{}");
                    case "DELETE" -> httpClient.deleteWithStatus(fullUrl, Map.of());
                    case "PATCH"  -> httpClient.patchWithStatus(fullUrl, Map.of(), "application/json", "{}");
                    default       -> null;
                };

                if (getResponse != null && testResponse != null
                        && getResponse.isSuccess()
                        && testResponse.isSuccess()) {

                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "HTTP Method Escalation - " + method + " Allowed Without Authorization",
                            String.format("The endpoint accepts %s requests without proper authorization. " +
                                    "This could allow unauthorized modification or deletion of resources. " +
                                    "GET was permitted and %s was also permitted without elevated privilege.",
                                    method, method),
                            Severity.HIGH,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Explicitly validate HTTP method permissions for each endpoint. Do not rely on " +
                            "route configuration alone. Ensure that state-changing methods (PUT, DELETE, PATCH) " +
                            "require appropriate authorization even when the GET counterpart is public."
                    );
                    finding.setRequestDetails(method + " " + fullUrl);
                    finding.setResponseDetails("HTTP " + testResponse.getStatusCode());
                    findings.add(finding);
                }
            } catch (Exception e) {
                logger.debug("Error testing HTTP method escalation ({}) on {}: {}", method, endpoint, e.getMessage());
            }
        }

        return findings;
    }
}
