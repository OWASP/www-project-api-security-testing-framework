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
import org.owasp.astf.core.discovery.PathTemplateResolver;
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

        // Centralized in PathTemplateResolver — Scanner already calls this for every endpoint
        // before test cases run, so in normal operation this is a fast no-op; it's called here
        // too so BOLA still resolves correctly when invoked directly (e.g. in unit tests) without
        // going through Scanner first.
        EndpointInfo resolvedEndpoint = PathTemplateResolver.resolve(endpoint, httpClient);

        findings.addAll(testCrossUserAccess(resolvedEndpoint, httpClient));
        findings.addAll(testNumericIdManipulation(resolvedEndpoint, httpClient));
        findings.addAll(testUuidManipulation(resolvedEndpoint, httpClient));

        return findings;
    }

    /**
     * Tests real cross-user BOLA: whether a second, distinct authenticated identity (configured
     * via {@code --secondary-token}) can access the exact same object — no ID substitution
     * involved — that the primary identity can access. Unlike {@link #testNumericIdManipulation}
     * and {@link #testUuidManipulation}, which only prove a single identity can swap IDs, this
     * proves the stronger claim BOLA actually names: a different user's credentials reading an
     * object without demonstrated ownership of it.
     * <p>
     * Skips entirely when no secondary identity is configured — {@link HttpClient#getSecondaryAuthHeaders()}
     * returns an empty map in that case, and the single-identity checks above remain the fallback.
     *
     * Unlike {@link #testNumericIdManipulation}/{@link #testUuidManipulation}, which need a
     * numeric/UUID value to substitute an alternative into, this check only compares two
     * identities against the same URL — so a successfully-resolved non-numeric, non-UUID value
     * (a username, slug, or title — see {@link EndpointInfo#isResolvedFromTemplate()}) is just
     * as valid a target here as a numeric/UUID one.
     */
    private List<Finding> testCrossUserAccess(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        Map<String, String> secondaryHeaders = httpClient.getSecondaryAuthHeaders();
        if (secondaryHeaders.isEmpty()) {
            return findings;
        }

        // Only meaningful for endpoints that identify a specific object and that the scan
        // considers to require authentication in the first place.
        if (!endpoint.isRequiresAuthentication()) {
            return findings;
        }
        boolean hasNumericId = NUMERIC_ID_PATTERN.matcher(endpoint.getPath()).find();
        boolean hasUuid = UUID_PATTERN.matcher(endpoint.getPath()).find();
        if (!hasNumericId && !hasUuid && !endpoint.isResolvedFromTemplate()) {
            return findings;
        }

        try {
            HttpResponse primaryResponse = makeRequest(endpoint, endpoint.getFullUrl(), httpClient, Map.of());
            HttpResponse secondaryResponse = makeRequest(endpoint, endpoint.getFullUrl(), httpClient, secondaryHeaders);

            if (primaryResponse != null && secondaryResponse != null
                    && primaryResponse.isSuccess()
                    && secondaryResponse.isSuccess()
                    && !secondaryResponse.isNotFound()) {

                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Broken Object Level Authorization (Cross-User Access Confirmed)",
                        String.format("A second, distinct authenticated identity was able to access " +
                                "'%s' — the same object the primary identity can access — without any " +
                                "ID substitution. This is direct evidence of a missing object-level " +
                                "authorization check, not an inference from ID guessing.",
                                endpoint.getPath()),
                        Severity.CRITICAL,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Verify that every object-returning endpoint checks the authenticated caller's " +
                        "ownership of or explicit permission for the specific object requested, not merely " +
                        "that the caller is authenticated at all."
                );
                finding.setRequestDetails(endpoint.getMethod() + " " + endpoint.getFullUrl() +
                        " — requested with two distinct identities (primary and secondary tokens)");
                finding.setResponseDetails("Primary identity status: " + primaryResponse.getStatusCode() +
                        "\nSecondary identity status: " + secondaryResponse.getStatusCode());
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing cross-user BOLA on {}: {}", endpoint, e.getMessage());
        }

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
        return makeRequest(endpoint, url, httpClient, Map.of());
    }

    /**
     * Same as {@link #makeRequest(EndpointInfo, String, HttpClient)}, but with a caller-supplied
     * header override — used by {@link #testCrossUserAccess} to substitute the secondary
     * identity's Authorization header for a single request without touching the client's
     * default identity.
     */
    private HttpResponse makeRequest(EndpointInfo endpoint, String url, HttpClient httpClient,
                                      Map<String, String> headers) throws IOException {
        return switch (endpoint.getMethod().toUpperCase()) {
            case "GET"    -> httpClient.getWithStatus(url, headers);
            case "POST"   -> httpClient.postWithStatus(url, headers, endpoint.getContentType(),
                                endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}");
            case "PUT"    -> httpClient.putWithStatus(url, headers, endpoint.getContentType(),
                                endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}");
            case "DELETE" -> httpClient.deleteWithStatus(url, headers);
            default       -> httpClient.getWithStatus(url, headers);
        };
    }

    private String buildUrl(EndpointInfo endpoint, String path) {
        String base = endpoint.getBaseUrl();
        if (base == null || base.isEmpty()) return path;
        base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        return base + (path.startsWith("/") ? path : "/" + path);
    }
}
