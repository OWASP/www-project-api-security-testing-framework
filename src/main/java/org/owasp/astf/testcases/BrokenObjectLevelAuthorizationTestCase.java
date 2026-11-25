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
     * Skips entirely when no secondary identity is configured ({@link HttpClient#hasSecondaryIdentity()}
     * is false), and the single-identity checks above remain the fallback.
     * <p>
     * The secondary request is sent with {@link HttpClient#sendWithStatusAsSecondary}, which
     * carries only the secondary token: none of the primary identity's API key, custom headers (other
     * than Accept, Content-Type, User-Agent, Accept-Language and Accept-Encoding) or cookies, so the
     * success cannot come from the primary identity. If that request is rejected with 401/403 and
     * the scan has an application-level credential (the configured API key, or a custom header
     * named like an application or gateway key), as API gateways that need an application key
     * besides the user's token do, the request is sent again with the secondary token plus that
     * application credential, still without the primary token, cookies or other custom headers,
     * and the finding says which way the secondary request was sent.
     *
     * Unlike {@link #testNumericIdManipulation}/{@link #testUuidManipulation}, which need a
     * numeric/UUID value to substitute an alternative into, this check only compares two
     * identities against the same URL — so a successfully-resolved non-numeric, non-UUID value
     * (a username, slug, or title — see {@link EndpointInfo#isResolvedFromTemplate()}) is just
     * as valid a target here as a numeric/UUID one.
     */
    private List<Finding> testCrossUserAccess(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!httpClient.hasSecondaryIdentity()) {
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
                findings.addAll(testCrossUserWrite(endpoint, httpClient));
            } else {
                findings.addAll(testCrossUserRead(endpoint, httpClient));
            }
        } catch (Exception e) {
            logger.debug("Error testing cross-user BOLA on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }
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
    private List<Finding> testCrossUserRead(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        List<Finding> findings = new ArrayList<>();
        // This path is only taken for a state-changing method when --allow-destructive is NOT set, so
        // a state-changing endpoint is always probed with a GET here.
        boolean readOnly = isStateChanging(endpoint);
        String url = endpoint.getFullUrl();

        HttpResponse primaryResponse = readOrRequest(endpoint, url, httpClient, Map.of());
        if (primaryResponse == null || !primaryResponse.isSuccess()) {
            if (readOnly) {
                findings.add(heldBackFinding(endpoint, primaryResponse));
            }
            return findings;
        }

        HttpResponse secondaryResponse = makeSecondaryRequest(endpoint, url, httpClient, false, readOnly);

        // Behind an API gateway that requires an application API key from every caller in
        // addition to the user's bearer token, the secondary token alone is always rejected.
        // Try again with the secondary token plus the application credential (never the
        // primary token, cookies or other custom headers) so the check still runs there.
        HttpResponse bareSecondaryResponse = secondaryResponse;
        boolean withApplicationCredentials = false;
        if (secondaryResponse != null
                && (secondaryResponse.isUnauthorized() || secondaryResponse.isForbidden())
                && httpClient.hasApplicationCredentials()) {
            secondaryResponse = makeSecondaryRequest(endpoint, url, httpClient, true, readOnly);
            withApplicationCredentials = true;
        }

        String probeNote = readOnly
                ? " The check used a read-only GET on the URL of this " + endpoint.getMethod() + " endpoint; the "
                  + endpoint.getMethod() + " itself was not sent (use --allow-destructive against test accounts to send it)."
                : "";
        String sentMethod = readOnly ? "GET" : endpoint.getMethod();

        // Last resort, so 2.1.0 never finds less than 2.0.2: if the secondary-only request (and the
        // application-credential variant) was rejected, send the request as 2.0.2 did, the primary
        // request with only the Authorization header replaced by the secondary token. Other custom
        // headers and cookies ride along then, so a success cannot be pinned on the secondary
        // identity alone and is reported at HIGH, listing what was sent.
        List<String> riding = httpClient.getHeaderNamesBesidesAuthorization(url);
        if (secondaryResponse != null && !secondaryResponse.isSuccess()
                && secondaryResponse.getStatusCode() >= 400 && secondaryResponse.getStatusCode() < 500
                && !riding.isEmpty()) {
            HttpResponse legacyResponse = readOrRequest(endpoint, url, httpClient,
                    httpClient.getSecondaryAuthHeaders());
            if (legacyResponse != null && legacyResponse.isSuccess() && !legacyResponse.isNotFound()) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Broken Object Level Authorization (Cross-User Access, other configured headers kept)",
                        String.format("A request carrying the second identity's token in place of the " +
                                "Authorization header was able to access '%s', the same object the primary " +
                                "identity can access. The secondary token alone was rejected (HTTP %d), so the " +
                                "other configured headers or cookies sent with it may identify the primary " +
                                "user, and the access cannot be attributed to the secondary identity alone.%s",
                                endpoint.getPath(), secondaryResponse.getStatusCode(), probeNote),
                        Severity.HIGH,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        CROSS_USER_REMEDIATION
                );
                finding.setRequestDetails(sentMethod + " " + url +
                        " (primary request with only the Authorization header replaced by the secondary token; "
                        + "still sent: " + String.join(", ", riding) + ")");
                finding.setResponseDetails("Primary identity status: " + primaryResponse.getStatusCode() +
                        "\nSecondary token alone: " + secondaryResponse.getStatusCode() +
                        "\nSecondary token with the other headers kept: " + legacyResponse.getStatusCode());
                findings.add(finding);
                return findings;
            }
        }

        if (secondaryResponse == null || !secondaryResponse.isSuccess() || secondaryResponse.isNotFound()) {
            return findings;
        }

        // Two 2xx responses do not prove BOLA: a public object answers everyone. An anonymous request
        // for the same object means there is no object-level boundary to break.
        HttpResponse anonymousResponse = httpClient.getWithStatusNoAuth(url);
        if (anonymousResponse != null && anonymousResponse.isSuccess()
                && sameObject(primaryResponse.getBody(), anonymousResponse.getBody())) {
            logger.debug("Cross-user BOLA on {} not reported: the object is also returned without credentials " +
                    "(public object; missing authentication is reported by ASTF-API2-2023)", endpoint);
            return findings;
        }

        boolean sameObject = sameObject(primaryResponse.getBody(), secondaryResponse.getBody());
        Finding finding;
        if (sameObject && withApplicationCredentials) {
            finding = createGatewayCrossUserFinding(endpoint, httpClient, primaryResponse,
                    bareSecondaryResponse, secondaryResponse, readOnly);
        } else if (sameObject) {
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
            finding.setRequestDetails(sentMethod + " " + url +
                    " (requested with two distinct identities: the primary credentials, then the " +
                    "secondary token alone; and with no credentials)");
            finding.setResponseDetails("Primary identity status: " + primaryResponse.getStatusCode() +
                    "\nSecondary identity status: " + secondaryResponse.getStatusCode() +
                    "\nAnonymous status: " + (anonymousResponse != null ? anonymousResponse.getStatusCode() : "not sent"));
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
            finding.setRequestDetails(sentMethod + " " + url +
                    " (requested with the primary credentials, the secondary token"
                    + (withApplicationCredentials ? " plus the application credential" : " alone")
                    + ", and no credentials)");
            finding.setResponseDetails("Primary identity status: " + primaryResponse.getStatusCode() +
                    "\nSecondary identity status: " + secondaryResponse.getStatusCode() +
                    "\nAnonymous status: " + (anonymousResponse != null ? anonymousResponse.getStatusCode() : "not sent") +
                    "\nSecondary received primary's object: false");
        }
        findings.add(finding);
        return findings;
    }

    /**
     * Destructive cross-user check, only with {@code --allow-destructive}. The secondary identity's
     * request is sent first: on a stateful API a DELETE or one-time update that the primary identity
     * ran first would leave nothing for the secondary identity to act on, hiding the bug. A read-only
     * GET by the primary identity afterwards records whether the object was changed or removed.
     * The secondary identity is sent the way {@link #testCrossUserRead} sends it (token only, then
     * with the application credential behind a gateway). The "other headers kept" fallback is not
     * used here: it would send the real method with the primary's headers and cookies attached.
     */
    private List<Finding> testCrossUserWrite(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String url = endpoint.getFullUrl();

        HttpResponse secondaryResponse = makeSecondaryRequest(endpoint, url, httpClient, false, false);
        boolean withApplicationCredentials = false;
        if (secondaryResponse != null
                && (secondaryResponse.isUnauthorized() || secondaryResponse.isForbidden())
                && httpClient.hasApplicationCredentials()) {
            secondaryResponse = makeSecondaryRequest(endpoint, url, httpClient, true, false);
            withApplicationCredentials = true;
        }
        if (secondaryResponse == null || !secondaryResponse.isSuccess() || secondaryResponse.isNotFound()) {
            return findings;
        }
        HttpResponse ownerFollowUp = httpClient.getWithStatus(url, Map.of());

        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                "Broken Object Level Authorization (Cross-User Access Confirmed)",
                String.format("A second, distinct authenticated identity's %s to '%s', an object reachable by " +
                        "the primary identity, was accepted without any ID substitution. This is direct evidence " +
                        "of a missing object-level authorization check on a state-changing operation.%s",
                        endpoint.getMethod(), endpoint.getPath(),
                        withApplicationCredentials
                                ? " The request carried the secondary token plus the application credential ("
                                  + String.join(", ", httpClient.getApplicationCredentialHeaderNames())
                                  + "), and no primary token, cookie or other custom header."
                                : ""),
                Severity.CRITICAL,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                CROSS_USER_REMEDIATION
        );
        finding.setRequestDetails(endpoint.getMethod() + " " + url + " (sent with the secondary token"
                + (withApplicationCredentials ? " plus the application credential" : "")
                + " and --allow-destructive, then GET with the primary token)");
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

    /**
     * Builds the cross-user finding for a secondary request that was only accepted with the
     * application credential added. A control request with the application credential alone (no
     * bearer token) shows whether the success needs the secondary user at all: if the control is
     * rejected, the secondary user's token was what got the object (CRITICAL, as for a bare
     * secondary request); if it is accepted, the application key alone reaches the object and the
     * result is reported at MEDIUM with that stated; if it could not be sent, at HIGH.
     */
    private Finding createGatewayCrossUserFinding(EndpointInfo endpoint, HttpClient httpClient,
                                                  HttpResponse primaryResponse, HttpResponse bareSecondaryResponse,
                                                  HttpResponse secondaryResponse, boolean readOnly) {
        String url = endpoint.getFullUrl();
        String credentialNames = String.join(", ", httpClient.getApplicationCredentialHeaderNames());

        HttpResponse controlResponse = null;
        try {
            controlResponse = makeApplicationCredentialOnlyRequest(endpoint, url, httpClient, readOnly);
        } catch (Exception e) {
            logger.debug("Application-credential-only control request on {} failed: {}", endpoint, e.getMessage());
        }

        String title;
        Severity severity;
        String description;
        if (controlResponse != null && controlResponse.isSuccess()) {
            title = "Broken Object Level Authorization (Cross-User Access, application API key alone also accepted)";
            severity = Severity.MEDIUM;
            description = String.format("A second, distinct identity's bearer token sent with the scan's " +
                    "application credential (%s) was able to access '%s', the same object the primary " +
                    "identity can access. The application credential alone, with no bearer token, was " +
                    "also accepted, so this access may not depend on the user at all: the object is " +
                    "reachable by anyone holding the application credential.", credentialNames, endpoint.getPath());
        } else {
            boolean controlRejected = controlResponse != null;
            title = "Broken Object Level Authorization (Cross-User Access Confirmed, secondary token with the application API key)";
            severity = controlRejected ? Severity.CRITICAL : Severity.HIGH;
            description = String.format("A second, distinct authenticated identity was able to access " +
                    "'%s', the same object the primary identity can access, without any ID substitution. " +
                    "The API requires an application credential (%s) in addition to the user's bearer " +
                    "token, so the secondary request carried the secondary token plus that application " +
                    "credential; it carried no primary bearer token, cookie or other custom header. %s",
                    endpoint.getPath(), credentialNames,
                    controlRejected
                            ? "The application credential alone was rejected, so the access depends on the secondary user's token."
                            : "Whether the application credential alone is accepted could not be checked.");
        }

        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                title,
                description,
                severity,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                CROSS_USER_REMEDIATION
        );
        finding.setRequestDetails((readOnly ? "GET" : endpoint.getMethod()) + " " + url +
                " (requested with two distinct identities: the primary credentials, then the secondary " +
                "token alone, which was rejected, then the secondary token plus the application credential " +
                credentialNames + " with no primary bearer token, cookies or other custom headers; " +
                "control: the application credential alone with no bearer token)");
        finding.setResponseDetails("Primary identity status: " + primaryResponse.getStatusCode() +
                "\nSecondary identity status (secondary token only): " + bareSecondaryResponse.getStatusCode() +
                "\nSecondary identity status (secondary token plus application credential): " +
                secondaryResponse.getStatusCode() +
                "\nApplication credential only (no bearer token) status: " +
                (controlResponse != null ? String.valueOf(controlResponse.getStatusCode()) : "not obtained"));
        return finding;
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
     * Same request as {@link #makeRequest(EndpointInfo, String, HttpClient, Map)}, sent as the
     * secondary identity only (see {@link HttpClient#sendWithStatusAsSecondary}), or, with
     * {@code withApplicationCredentials}, as the secondary identity plus the scan's application
     * credential (see {@link HttpClient#sendWithStatusAsSecondaryWithApplicationCredentials}).
     * With {@code readOnly} the request is a GET on the same URL, so a state-changing endpoint is
     * never modified (see {@code --allow-destructive}).
     */
    private HttpResponse makeSecondaryRequest(EndpointInfo endpoint, String url, HttpClient httpClient,
                                              boolean withApplicationCredentials, boolean readOnly)
            throws IOException {
        RequestSender sender = withApplicationCredentials
                ? httpClient::sendWithStatusAsSecondaryWithApplicationCredentials
                : httpClient::sendWithStatusAsSecondary;
        return sendSameAsPrimary(endpoint, url, readOnly, sender);
    }

    /** Same request with the application credential only (see {@link HttpClient#sendWithStatusApplicationCredentialsOnly}). */
    private HttpResponse makeApplicationCredentialOnlyRequest(EndpointInfo endpoint, String url, HttpClient httpClient,
                                                              boolean readOnly) throws IOException {
        return sendSameAsPrimary(endpoint, url, readOnly, httpClient::sendWithStatusApplicationCredentialsOnly);
    }

    @FunctionalInterface
    private interface RequestSender {
        HttpResponse send(String method, String url, String contentType, String body) throws IOException;
    }

    private HttpResponse sendSameAsPrimary(EndpointInfo endpoint, String url, boolean readOnly, RequestSender sender)
            throws IOException {
        if (readOnly) {
            return sender.send("GET", url, null, null);
        }
        String method = endpoint.getMethod().toUpperCase(Locale.ROOT);
        return switch (method) {
            case "POST", "PUT", "PATCH" -> sender.send(method, url, endpoint.getContentType(), resolveRequestBody(endpoint));
            case "DELETE" -> sender.send("DELETE", url, null, null);
            default -> sender.send("GET", url, null, null);
        };
    }

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
