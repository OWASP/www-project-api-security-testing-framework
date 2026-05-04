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
 * Tests for API1:2023 Broken Object Level Authorization (BOLA/IDOR).
 *
 * BOLA occurs when an API endpoint receives an object identifier from the client and
 * does not validate that the requesting user has permission to access that specific object.
 * Attackers can substitute their own resource ID with another user's resource ID to gain
 * unauthorized access.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/">OWASP API1:2023</a>
 */
public class BrokenObjectLevelAuthorizationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(BrokenObjectLevelAuthorizationTestCase.class);

    // Patterns for numeric IDs, UUIDs, and alphanumeric IDs in paths
    private static final Pattern NUMERIC_ID_PATTERN = Pattern.compile("/(\\d+)(/|$)");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)",
            Pattern.CASE_INSENSITIVE);

    // IDs to substitute when testing for BOLA
    private static final List<String> ALTERNATIVE_NUMERIC_IDS = List.of("1", "2", "100", "999", "0");
    private static final String ALTERNATIVE_UUID = "00000000-0000-0000-0000-000000000001";

    @Override
    public String getId() {
        return "ASTF-API1-2023";
    }

    @Override
    public String getName() {
        return "Broken Object Level Authorization";
    }

    @Override
    public String getDescription() {
        return "Tests for BOLA/IDOR vulnerabilities by attempting to access objects belonging " +
               "to other users by manipulating resource identifiers in API paths.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testNumericIdManipulation(endpoint, httpClient));
        findings.addAll(testUuidManipulation(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testNumericIdManipulation(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String path = endpoint.getPath();
        Matcher matcher = NUMERIC_ID_PATTERN.matcher(path);

        if (!matcher.find()) {
            return findings;
        }

        String originalId = matcher.group(1);

        // Try accessing the same endpoint with different IDs
        for (String altId : ALTERNATIVE_NUMERIC_IDS) {
            if (altId.equals(originalId)) continue;

            String altPath = path.replaceFirst("/" + originalId + "(/|$)", "/" + altId + "$1");
            String altUrl = buildUrl(endpoint, altPath);

            try {
                HttpResponse originalResponse = makeRequest(endpoint, endpoint.getFullUrl(), httpClient);
                HttpResponse altResponse = makeRequest(endpoint, altUrl, httpClient);

                if (originalResponse != null && altResponse != null
                        && originalResponse.isSuccess()
                        && altResponse.isSuccess()
                        && !altResponse.isNotFound()) {

                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Broken Object Level Authorization (BOLA/IDOR)",
                            String.format("The API endpoint appears to return data for resource ID '%s' " +
                                    "when originally requested with ID '%s', suggesting that object-level " +
                                    "authorization is not enforced.", altId, originalId),
                            Severity.HIGH,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Implement object-level authorization checks for every API endpoint that " +
                            "accesses a data source using user-supplied identifiers. Validate that the " +
                            "requesting user has permission to access the specific object requested."
                    );
                    finding.setRequestDetails("Original: " + endpoint.getMethod() + " " + endpoint.getFullUrl() +
                            "\nModified: " + endpoint.getMethod() + " " + altUrl);
                    finding.setResponseDetails("Original status: " + originalResponse.getStatusCode() +
                            "\nModified status: " + altResponse.getStatusCode());
                    findings.add(finding);
                    break; // One finding per endpoint is enough
                }
            } catch (Exception e) {
                logger.debug("Error testing BOLA on {} with ID {}: {}", endpoint, altId, e.getMessage());
            }
        }

        return findings;
    }

    private List<Finding> testUuidManipulation(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String path = endpoint.getPath();
        Matcher matcher = UUID_PATTERN.matcher(path);

        if (!matcher.find()) {
            return findings;
        }

        String originalUuid = matcher.group(1);
        String altPath = path.replace(originalUuid, ALTERNATIVE_UUID);
        String altUrl = buildUrl(endpoint, altPath);

        try {
            HttpResponse originalResponse = makeRequest(endpoint, endpoint.getFullUrl(), httpClient);
            HttpResponse altResponse = makeRequest(endpoint, altUrl, httpClient);

            if (originalResponse != null && altResponse != null
                    && originalResponse.isSuccess()
                    && altResponse.isSuccess()
                    && !altResponse.isNotFound()) {

                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Broken Object Level Authorization (UUID Substitution)",
                        String.format("The API endpoint responded successfully when the UUID '%s' " +
                                "was substituted with '%s', indicating insufficient authorization checks.",
                                originalUuid, ALTERNATIVE_UUID),
                        Severity.HIGH,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Validate that the authenticated user owns or has explicit permission to access " +
                        "each resource identified by UUID. Do not rely solely on the secrecy of UUIDs."
                );
                finding.setRequestDetails("Original UUID: " + originalUuid + "\nAlternative UUID: " + ALTERNATIVE_UUID);
                finding.setResponseDetails("Both returned HTTP " + altResponse.getStatusCode());
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing UUID BOLA on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private HttpResponse makeRequest(EndpointInfo endpoint, String url, HttpClient httpClient) throws IOException {
        return switch (endpoint.getMethod().toUpperCase()) {
            case "GET"    -> httpClient.getWithStatus(url, Map.of());
            case "POST"   -> httpClient.postWithStatus(url, Map.of(), endpoint.getContentType(),
                                endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}");
            case "PUT"    -> httpClient.putWithStatus(url, Map.of(), endpoint.getContentType(),
                                endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}");
            case "DELETE" -> httpClient.deleteWithStatus(url, Map.of());
            default       -> httpClient.getWithStatus(url, Map.of());
        };
    }

    private String buildUrl(EndpointInfo endpoint, String path) {
        String base = endpoint.getBaseUrl();
        if (base == null || base.isEmpty()) return path;
        base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        return base + (path.startsWith("/") ? path : "/" + path);
    }
}
