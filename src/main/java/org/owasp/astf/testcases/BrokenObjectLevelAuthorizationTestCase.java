package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    // Used to build a realistic PUT/POST/PATCH body when the endpoint has no discovered request
    // body — found necessary by live-testing VAmPI's password-change endpoint: sending "{}" let
    // the request reach the endpoint, but never actually exercised the password-change semantics
    // the vulnerability is about, understating what "cross-user access confirmed" should mean for
    // a state-changing request. Extra fields an endpoint doesn't expect are typically ignored, so
    // sending all of these together costs nothing.
    private static final List<Map.Entry<String, String>> COMMON_STATE_CHANGE_BODY_FIELDS = List.of(
            Map.entry("password", "N3wP@ssw0rd!"),
            Map.entry("new_password", "N3wP@ssw0rd!"),
            Map.entry("email", "test@example.com"),
            Map.entry("name", "Test User")
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    // AI-Generated Code - 2026-11-25 - Auto
    // This is AI generated code
    private static final ObjectMapper STATIC_MAPPER = new ObjectMapper();
    private static final Set<String> STATE_CHANGING_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");
    // Fields that name an object rather than describe it; used to recognise the same object in two
    // responses that differ only in viewer-specific fields.
    private static final Pattern IDENTIFIER_KEY = Pattern.compile(
            "(?i)^(id|_id|uuid|guid|.*[_-]id|.*Id|.*uuid|username|user_name|email|slug)$");
    private static final String CROSS_USER_REMEDIATION =
            "Verify that every object-returning endpoint checks the authenticated caller's " +
            "ownership of or explicit permission for the specific object requested, not merely " +
            "that the caller is authenticated at all.";

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
            if (isStateChanging(endpoint) && httpClient.isDestructiveTestingAllowed()) {
                findings.addAll(testCrossUserWrite(endpoint, httpClient, secondaryHeaders));
            } else {
                findings.addAll(testCrossUserRead(endpoint, httpClient, secondaryHeaders));
            }
        } catch (Exception e) {
            logger.debug("Error testing cross-user BOLA on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    // AI-Generated Code - 2026-11-25 - Auto
    // This is AI generated code
    /**
     * Read-only cross-user check. A state-changing endpoint is probed with GET on the same URL,
     * so the scan never modifies or deletes an object it does not own unless the operator passed
     * {@code --allow-destructive}.
     * <p>
     * Two 2xx status codes alone do not prove BOLA: a public object, or an endpoint that returns
     * each caller's own record whatever the ID, also answers 2xx to both identities. The result is
     * CRITICAL only when the secondary identity receives the primary identity's object (see
     * {@link #sameObject}) and an anonymous request does not; a 2xx with different content is
     * kept as MEDIUM so it can be checked by hand.
     */
    private List<Finding> testCrossUserRead(EndpointInfo endpoint, HttpClient httpClient,
                                            Map<String, String> secondaryHeaders) throws IOException {
        List<Finding> findings = new ArrayList<>();
        boolean readSubstitutedForWrite = isStateChanging(endpoint);
        String url = endpoint.getFullUrl();

        HttpResponse primaryResponse = readOrRequest(endpoint, url, httpClient, Map.of());
        if (primaryResponse == null || !primaryResponse.isSuccess()) {
            if (readSubstitutedForWrite) {
                findings.add(heldBackFinding(endpoint, primaryResponse));
            }
            return findings;
        }

        HttpResponse secondaryResponse = readOrRequest(endpoint, url, httpClient, secondaryHeaders);
        if (secondaryResponse == null || !secondaryResponse.isSuccess() || secondaryResponse.isNotFound()) {
            return findings;
        }

        HttpResponse anonymousResponse = isStateChanging(endpoint) || "GET".equalsIgnoreCase(endpoint.getMethod())
                ? httpClient.getWithStatusNoAuth(url)
                : null;
        if (anonymousResponse != null && anonymousResponse.isSuccess()
                && sameObject(primaryResponse.getBody(), anonymousResponse.getBody())) {
            logger.debug("Cross-user BOLA on {} not reported: the object is also returned without credentials " +
                    "(public object; missing authentication is reported by ASTF-API2-2023)", endpoint);
            return findings;
        }

        String probeNote = readSubstitutedForWrite
                ? " The check used a read-only GET on the URL of this " + endpoint.getMethod() + " endpoint; the "
                  + endpoint.getMethod() + " itself was not sent (use --allow-destructive against test accounts to send it)."
                : "";

        Finding finding;
        if (sameObject(primaryResponse.getBody(), secondaryResponse.getBody())) {
            finding = new Finding(
                    UUID.randomUUID().toString(),
                    "Broken Object Level Authorization (Cross-User Access Confirmed)",
                    String.format("A second, distinct authenticated identity received the same object as the " +
                            "primary identity from '%s', without any ID substitution, and the object is not " +
                            "returned to an anonymous request. This is direct evidence of a missing " +
                            "object-level authorization check, not an inference from ID guessing.%s",
                            endpoint.getPath(), probeNote),
                    Severity.CRITICAL,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    CROSS_USER_REMEDIATION
            );
        } else {
            finding = new Finding(
                    UUID.randomUUID().toString(),
                    "Broken Object Level Authorization (Cross-User Access Not Confirmed)",
                    String.format("Both identities received a 2xx response from '%s', but the secondary identity's " +
                            "response does not contain the primary identity's object. The endpoint may return each " +
                            "caller's own data regardless of the ID in the path, which is not BOLA. Compare the two " +
                            "responses by hand before reporting.%s", endpoint.getPath(), probeNote),
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    CROSS_USER_REMEDIATION
            );
        }
        finding.setRequestDetails((readSubstitutedForWrite ? "GET" : endpoint.getMethod()) + " " + url +
                " — requested with the primary token, the secondary token, and no credentials");
        finding.setResponseDetails("Primary identity status: " + primaryResponse.getStatusCode() +
                "\nSecondary identity status: " + secondaryResponse.getStatusCode() +
                "\nAnonymous status: " + (anonymousResponse != null ? anonymousResponse.getStatusCode() : "not sent") +
                "\nSecondary received primary's object: " + sameObject(primaryResponse.getBody(), secondaryResponse.getBody()));
        findings.add(finding);
        return findings;
    }

    /**
     * Destructive cross-user check, only with {@code --allow-destructive}. The secondary identity's
     * request is sent first: on a stateful API a DELETE or one-time update that the primary identity
     * ran first would leave nothing for the secondary identity to act on, hiding the bug. A read-only
     * GET by the primary identity afterwards records whether the object was changed or removed.
     */
    private List<Finding> testCrossUserWrite(EndpointInfo endpoint, HttpClient httpClient,
                                             Map<String, String> secondaryHeaders) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String url = endpoint.getFullUrl();

        HttpResponse secondaryResponse = makeRequest(endpoint, url, httpClient, secondaryHeaders);
        if (secondaryResponse == null || !secondaryResponse.isSuccess() || secondaryResponse.isNotFound()) {
            return findings;
        }
        HttpResponse ownerFollowUp = httpClient.getWithStatus(url, Map.of());

        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                "Broken Object Level Authorization (Cross-User Access Confirmed)",
                String.format("A second, distinct authenticated identity's %s to '%s' — an object reachable by " +
                        "the primary identity — was accepted without any ID substitution. This is direct evidence " +
                        "of a missing object-level authorization check on a state-changing operation.",
                        endpoint.getMethod(), endpoint.getPath()),
                Severity.CRITICAL,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                CROSS_USER_REMEDIATION
        );
        finding.setRequestDetails(endpoint.getMethod() + " " + url + " — sent with the secondary token " +
                "(--allow-destructive), then GET with the primary token");
        finding.setResponseDetails("Secondary identity status: " + secondaryResponse.getStatusCode() +
                "\nPrimary identity follow-up GET status: " +
                (ownerFollowUp != null ? ownerFollowUp.getStatusCode() : "no response") +
                (ownerFollowUp != null && ownerFollowUp.isNotFound()
                        ? " (the object no longer exists for its owner)" : ""));
        findings.add(finding);
        return findings;
    }

    private Finding heldBackFinding(EndpointInfo endpoint, HttpResponse readProbe) {
        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                "Broken Object Level Authorization Check Held Back (state-changing method)",
                String.format("The cross-user check for %s %s was not run because it would modify or delete " +
                        "an object, and the read-only GET used instead could not reach the object (status %s). " +
                        "Re-run with --allow-destructive against test accounts whose data may be changed to " +
                        "send the %s itself.", endpoint.getMethod(), endpoint.getPath(),
                        readProbe != null ? readProbe.getStatusCode() : "no response", endpoint.getMethod()),
                Severity.INFO,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Run the destructive cross-user check against an isolated environment, or verify this endpoint's " +
                "object-level authorization manually."
        );
        finding.setRequestDetails("GET " + endpoint.getFullUrl() + " — read-only substitute for " + endpoint.getMethod());
        return finding;
    }

    /**
     * True when both bodies describe the same object: identical text, identical JSON, or, for JSON
     * objects, every identifier-like field of {@code expected} (id, uuid, username, email, ...) is
     * present in {@code actual} with the same value. Viewer-specific fields such as timestamps do
     * not make two copies of one object look different.
     */
    static boolean sameObject(String expected, String actual) {
        if (expected == null || actual == null || expected.isBlank() || actual.isBlank()) {
            return false;
        }
        if (expected.trim().equals(actual.trim())) {
            return true;
        }
        try {
            JsonNode a = STATIC_MAPPER.readTree(expected);
            JsonNode b = STATIC_MAPPER.readTree(actual);
            if (a.equals(b)) {
                return true;
            }
            JsonNode objA = unwrapSingleObject(a);
            JsonNode objB = unwrapSingleObject(b);
            if (objA == null || objB == null) {
                return false;
            }
            int identifiers = 0;
            var fields = objA.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                if (!field.getValue().isValueNode() || !IDENTIFIER_KEY.matcher(field.getKey()).matches()) {
                    continue;
                }
                identifiers++;
                JsonNode other = objB.get(field.getKey());
                if (other == null || !other.equals(field.getValue())) {
                    return false;
                }
            }
            return identifiers > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static JsonNode unwrapSingleObject(JsonNode node) {
        if (node == null || !node.isObject()) {
            return null;
        }
        if (node.size() == 1) {
            JsonNode only = node.elements().next();
            if (only.isObject()) {
                return only;
            }
        }
        return node;
    }

    private static boolean isStateChanging(EndpointInfo endpoint) {
        return STATE_CHANGING_METHODS.contains(endpoint.getMethod().toUpperCase(Locale.ROOT));
    }

    /**
     * Sends the endpoint's own method when it is read-only or {@code --allow-destructive} is set;
     * otherwise sends a GET to the same URL.
     */
    private HttpResponse readOrRequest(EndpointInfo endpoint, String url, HttpClient httpClient,
                                       Map<String, String> headers) throws IOException {
        if (isStateChanging(endpoint) && !httpClient.isDestructiveTestingAllowed()) {
            return httpClient.getWithStatus(url, headers);
        }
        return makeRequest(endpoint, url, httpClient, headers);
    }

    private List<Finding> testNumericIdManipulation(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String path = endpoint.getPath();
        Matcher matcher = NUMERIC_ID_PATTERN.matcher(path);

        if (!matcher.find()) {
            return findings;
        }

        String originalId = matcher.group(1);
        String sentMethod = substitutionMethod(endpoint, httpClient);

        HttpResponse originalResponse;
        try {
            originalResponse = readOrRequest(endpoint, endpoint.getFullUrl(), httpClient, Map.of());
        } catch (Exception e) {
            logger.debug("Error testing BOLA on {}: {}", endpoint, e.getMessage());
            return findings;
        }

        // Try accessing the same endpoint with different IDs
        for (String altId : ALTERNATIVE_NUMERIC_IDS) {
            if (altId.equals(originalId)) continue;

            String altPath = path.replaceFirst("/" + originalId + "(/|$)", "/" + altId + "$1");
            String altUrl = buildUrl(endpoint, altPath);

            try {
                HttpResponse altResponse = readOrRequest(endpoint, altUrl, httpClient, Map.of());

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
                    finding.setRequestDetails("Original: " + sentMethod + " " + endpoint.getFullUrl() +
                            "\nModified: " + sentMethod + " " + altUrl);
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
            HttpResponse originalResponse = readOrRequest(endpoint, endpoint.getFullUrl(), httpClient, Map.of());
            HttpResponse altResponse = readOrRequest(endpoint, altUrl, httpClient, Map.of());

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
                finding.setRequestDetails(substitutionMethod(endpoint, httpClient) + " with original UUID: " + originalUuid +
                        "\nAlternative UUID: " + ALTERNATIVE_UUID);
                finding.setResponseDetails("Both returned HTTP " + altResponse.getStatusCode());
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing UUID BOLA on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private static String substitutionMethod(EndpointInfo endpoint, HttpClient httpClient) {
        return isStateChanging(endpoint) && !httpClient.isDestructiveTestingAllowed()
                ? "GET" : endpoint.getMethod().toUpperCase(Locale.ROOT);
    }

    /**
     * Sends the endpoint's own method with a caller-supplied header override — used by
     * {@link #testCrossUserAccess} to substitute the secondary identity's Authorization header for a
     * single request without touching the client's default identity. State-changing callers go
     * through {@link #readOrRequest} so this is only reached for them with {@code --allow-destructive}.
     */
    private HttpResponse makeRequest(EndpointInfo endpoint, String url, HttpClient httpClient,
                                      Map<String, String> headers) throws IOException {
        return switch (endpoint.getMethod().toUpperCase(Locale.ROOT)) {
            case "GET"    -> httpClient.getWithStatus(url, headers);
            case "POST"   -> httpClient.postWithStatus(url, headers, endpoint.getContentType(), resolveRequestBody(endpoint));
            case "PUT"    -> httpClient.putWithStatus(url, headers, endpoint.getContentType(), resolveRequestBody(endpoint));
            case "PATCH"  -> httpClient.patchWithStatus(url, headers, endpoint.getContentType(), resolveRequestBody(endpoint));
            case "DELETE" -> httpClient.deleteWithStatus(url, headers);
            default       -> httpClient.getWithStatus(url, headers);
        };
    }

    /**
     * Returns the endpoint's own discovered request body when it's a usable, non-empty JSON
     * object, otherwise builds a realistic body from common field names (see
     * {@link #COMMON_STATE_CHANGE_BODY_FIELDS}) rather than falling back to an empty {@code "{}"}
     * — an empty body reaches a PUT/POST endpoint but doesn't exercise its actual state-changing
     * behavior, which is exactly what {@link #testCrossUserAccess} needs to prove.
     */
    private String resolveRequestBody(EndpointInfo endpoint) {
        String discovered = endpoint.getRequestBody();
        if (discovered != null && !discovered.isBlank()) {
            try {
                JsonNode root = objectMapper.readTree(discovered);
                if (root.isObject() && root.size() > 0) {
                    return discovered;
                }
            } catch (Exception e) {
                logger.debug("Discovered request body for {} isn't valid JSON, using fallback: {}",
                        endpoint, e.getMessage());
            }
        }
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < COMMON_STATE_CHANGE_BODY_FIELDS.size(); i++) {
            if (i > 0) sb.append(",");
            Map.Entry<String, String> field = COMMON_STATE_CHANGE_BODY_FIELDS.get(i);
            sb.append("\"").append(field.getKey()).append("\":\"").append(field.getValue()).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private String buildUrl(EndpointInfo endpoint, String path) {
        String base = endpoint.getBaseUrl();
        if (base == null || base.isEmpty()) return path;
        base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        return base + (path.startsWith("/") ? path : "/" + path);
    }
}
