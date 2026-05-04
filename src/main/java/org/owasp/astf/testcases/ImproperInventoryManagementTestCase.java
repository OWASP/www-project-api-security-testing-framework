package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

/**
 * Tests for API9:2023 Improper Inventory Management.
 *
 * Organizations often expose more API endpoints than intended, including old/deprecated versions,
 * beta endpoints, and non-production environments. These untracked or forgotten endpoints may
 * lack the same security controls as production endpoints.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/">OWASP API9:2023</a>
 */
public class ImproperInventoryManagementTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(ImproperInventoryManagementTestCase.class);

    private static final List<String> OLD_VERSION_PREFIXES = List.of(
            "/v1/", "/v2/", "/v3/", "/v0/",
            "/api/v1/", "/api/v2/", "/api/v3/", "/api/v0/",
            "/api/v1.", "/api/v2.",
            "/v1.", "/v2.",
            "/beta/", "/alpha/", "/dev/",
            "/test/", "/staging/", "/legacy/", "/deprecated/",
            "/old/", "/archive/", "/backup/"
    );

    private static final List<String> EXPOSED_DOC_ENDPOINTS = List.of(
            "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
            "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs.json",
            "/v2/api-docs", "/v3/api-docs",
            "/redoc", "/docs", "/documentation",
            "/raml", "/api.raml", "/postman", "/postman-collection"
    );

    private static final Pattern VERSION_PATTERN = Pattern.compile("/v(\\d+)/");

    @Override
    public String getId() {
        return "ASTF-API9-2023";
    }

    @Override
    public String getName() {
        return "Improper Inventory Management";
    }

    @Override
    public String getDescription() {
        return "Tests for exposed deprecated API versions, shadow endpoints, untracked environments, " +
               "and API documentation endpoints that reveal internal API structure.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testOldApiVersions(endpoint, httpClient));
        findings.addAll(testExposedDocumentation(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testOldApiVersions(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        String path = endpoint.getPath();
        Matcher versionMatcher = VERSION_PATTERN.matcher(path);

        // Find the current version in the path
        if (!versionMatcher.find()) {
            return findings;
        }

        int currentVersion = Integer.parseInt(versionMatcher.group(1));
        String baseUrl = endpoint.getBaseUrl();

        if (baseUrl == null || baseUrl.isEmpty()) return findings;

        String cleanBase = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        // Try older versions
        for (int v = currentVersion - 1; v >= Math.max(0, currentVersion - 3); v--) {
            String oldPath = path.replaceFirst("/v" + currentVersion + "/", "/v" + v + "/");
            String oldUrl = cleanBase + oldPath;

            try {
                HttpResponse response = httpClient.getWithStatus(oldUrl, Map.of());

                if (response != null && response.isSuccess()) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Deprecated API Version Still Accessible",
                            String.format("API version v%d appears to still be accessible at '%s'. " +
                                    "Deprecated API versions may lack security patches and current " +
                                    "access controls applied to v%d.", v, oldPath, currentVersion),
                            Severity.MEDIUM,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Maintain an accurate API inventory. Properly deprecate and decommission old " +
                            "API versions. If old versions must remain, ensure they have equivalent security " +
                            "controls. Communicate deprecation timelines to API consumers."
                    );
                    finding.setRequestDetails(endpoint.getMethod() + " " + oldUrl);
                    finding.setResponseDetails("HTTP " + response.getStatusCode());
                    findings.add(finding);
                }
            } catch (Exception e) {
                logger.debug("Error testing old API version {} on {}: {}", v, oldUrl, e.getMessage());
            }
        }

        // Also try common non-versioned variations
        List<String> shadowPaths = List.of("/beta/", "/alpha/", "/dev/", "/test/");
        for (String shadow : shadowPaths) {
            String shadowPath = path.replaceFirst("/v\\d+/", shadow);
            if (shadowPath.equals(path)) continue;

            String shadowUrl = cleanBase + shadowPath;
            try {
                HttpResponse response = httpClient.getWithStatus(shadowUrl, Map.of());
                if (response != null && response.isSuccess()) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Shadow/Non-Production API Endpoint Accessible",
                            String.format("A non-production API endpoint '%s' is publicly accessible. " +
                                    "Shadow endpoints often bypass production security controls.", shadowPath),
                            Severity.HIGH,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Block access to non-production API environments from public networks. " +
                            "Ensure all API environments enforce equivalent security controls."
                    );
                    finding.setRequestDetails(endpoint.getMethod() + " " + shadowUrl);
                    findings.add(finding);
                }
            } catch (Exception e) {
                logger.debug("Error testing shadow path {} on {}: {}", shadowPath, shadowUrl, e.getMessage());
            }
        }

        return findings;
    }

    private List<Finding> testExposedDocumentation(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = endpoint.getBaseUrl();

        // Only run on root endpoint to avoid duplicate discoveries
        if (baseUrl == null || baseUrl.isEmpty()
                || (!endpoint.getPath().equals("/") && !endpoint.getPath().isEmpty())) {
            return findings;
        }

        String cleanBase = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;

        for (String docPath : EXPOSED_DOC_ENDPOINTS) {
            String testUrl = cleanBase + docPath;
            try {
                HttpResponse response = httpClient.getWithStatus(testUrl, Map.of());

                if (response != null && response.isSuccess() && !response.getBody().isEmpty()) {
                    boolean isApiSpec = response.getBody().contains("\"openapi\"")
                            || response.getBody().contains("\"swagger\"")
                            || response.getBody().contains("swagger:")
                            || response.getBody().contains("openapi:")
                            || response.getBody().contains("\"paths\"")
                            || response.getBody().contains("\"endpoints\"");

                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "API Documentation Publicly Exposed",
                            String.format("API documentation is publicly accessible at '%s'. " +
                                    "Exposed API documentation reveals all endpoints, parameters, " +
                                    "data models, and authentication methods to potential attackers%s.",
                                    docPath,
                                    isApiSpec ? " (confirmed API specification detected)" : ""),
                            Severity.LOW,
                            getId(),
                            "GET " + docPath,
                            "Restrict access to API documentation in production environments. " +
                            "Consider requiring authentication to view API documentation. " +
                            "At minimum, ensure documentation does not include production credentials or examples."
                    );
                    finding.setRequestDetails("GET " + testUrl);
                    finding.setResponseDetails("HTTP " + response.getStatusCode() +
                            "; API spec detected: " + isApiSpec);
                    findings.add(finding);
                }
            } catch (Exception e) {
                logger.debug("Error testing documentation endpoint {}: {}", testUrl, e.getMessage());
            }
        }

        return findings;
    }
}
