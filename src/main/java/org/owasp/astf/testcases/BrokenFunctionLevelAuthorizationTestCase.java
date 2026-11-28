package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.http.SoftNotFoundDetector;
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

    // A path segment that exactly matches one of these (case-insensitive) is a candidate for
    // privilege-tier substitution — swapping it for a higher-privilege keyword and replaying the
    // SAME request (same credentials, same ID, same method) at that alternate path. Found by
    // tracing crAPI's actual source: its real BFLA vulnerability is exactly this pattern —
    // DELETE /identity/api/v2/user/videos/{id} is a deliberate decoy that always returns
    // 403/404, while DELETE /identity/api/v2/admin/videos/{id} (same ID, same non-admin token)
    // succeeds with no role check at all. Appending a generic "/admin" to the base URL root
    // (see testAdminEndpointAccess) never finds this, since the vulnerable path only exists as a
    // sibling of an already-known, specific resource endpoint.
    private static final List<String> LOW_PRIVILEGE_SEGMENT_KEYWORDS = List.of("user", "customer", "member", "public");
    private static final List<String> HIGH_PRIVILEGE_SEGMENT_REPLACEMENTS = List.of(
            "admin", "administrator", "internal", "staff", "management", "superuser"
    );

    /**
     * Guards the admin-path probing below against targets that answer 2xx for every unknown path.
     * Held per instance so the baseline probe runs once per target for the whole scan rather than
     * once per endpoint.
     */
    private final SoftNotFoundDetector softNotFoundDetector = new SoftNotFoundDetector();

    /**
     * Admin paths already put through {@link #testAccessControlBypass} in this scan. The admin
     * probes run for every endpoint, so without this the bypass variants would be resent for each
     * one. Keyed by HttpClient so a new scan starts fresh, like the debug probes in
     * {@link SecurityMisconfigurationTestCase}.
     */
    private final Map<HttpClient, Set<String>> bypassAttempts = new WeakHashMap<>();

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
        findings.addAll(testPrivilegeTierPathSubstitution(endpoint, httpClient));

        return findings;
    }

    /**
     * Substitutes a low-privilege path segment (e.g. {@code /user/}) with a high-privilege one
     * (e.g. {@code /admin/}) in an otherwise identical, already-known resource path — same
     * method, same ID, same credentials — and checks whether the substituted path succeeds where
     * the original wouldn't (or where no elevated role should be able to succeed with a
     * non-elevated token). This is the "predictable REST naming" BFLA pattern named directly in
     * crAPI's own challenge doc ("leverage the predictable nature of REST APIs to find an admin
     * endpoint"), confirmed against crAPI's real source: the vulnerable endpoint only exists as
     * a same-shaped sibling of a known user-facing one, which {@link #testAdminEndpointAccess}
     * (root-relative admin paths only) can never reach.
     */
    List<Finding> testPrivilegeTierPathSubstitution(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = endpoint.getBaseUrl();
        if (baseUrl == null || baseUrl.isEmpty()) {
            return findings;
        }

        String path = endpoint.getPath();
        String[] segments = path.split("/");
        int targetIndex = -1;
        for (int i = 0; i < segments.length; i++) {
            if (LOW_PRIVILEGE_SEGMENT_KEYWORDS.stream().anyMatch(segments[i]::equalsIgnoreCase)) {
                targetIndex = i;
                break;
            }
        }
        if (targetIndex == -1) {
            return findings;
        }

        try {
            HttpResponse originalResponse = makeRequest(endpoint, endpoint.getFullUrl(), httpClient);

            for (String replacement : HIGH_PRIVILEGE_SEGMENT_REPLACEMENTS) {
                String[] altSegments = segments.clone();
                altSegments[targetIndex] = replacement;
                String altPath = String.join("/", altSegments);
                String altUrl = buildUrl(baseUrl, altPath);

                try {
                    HttpResponse altResponse = makeRequest(endpoint, altUrl, httpClient);

                    if (altResponse != null && altResponse.isSuccess() && isApiResponse(altResponse)
                            && (originalResponse == null || !originalResponse.isSuccess())) {

                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "Broken Function Level Authorization (Privilege-Tier Path Substitution)",
                                String.format("Replacing the '%s' path segment with '%s' in an otherwise " +
                                        "identical request (%s %s) succeeded using the same, non-elevated " +
                                        "credentials — indicating the higher-privilege-tier endpoint performs " +
                                        "no role check of its own.",
                                        segments[targetIndex], replacement, endpoint.getMethod(), path),
                                Severity.CRITICAL,
                                getId(),
                                endpoint.getMethod() + " " + path,
                                "Enforce role-based access control on every endpoint independently of naming " +
                                "convention. An endpoint's path (e.g. containing '/admin/') must never be the " +
                                "only thing distinguishing its authorization requirements from a sibling path."
                        );
                        finding.setRequestDetails("Original: " + endpoint.getMethod() + " " + endpoint.getFullUrl() +
                                "\nSubstituted: " + endpoint.getMethod() + " " + altUrl);
                        finding.setResponseDetails("Original status: " +
                                (originalResponse != null ? originalResponse.getStatusCode() : "n/a") +
                                "\nSubstituted status: " + altResponse.getStatusCode());
                        findings.add(finding);
                        return findings; // one confirmed instance is enough for this endpoint
                    }
                } catch (Exception e) {
                    logger.debug("Error testing privilege-tier substitution ({}) on {}: {}",
                            replacement, endpoint, e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.debug("Error testing privilege-tier path substitution on {}: {}", endpoint, e.getMessage());
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
            case "PATCH"  -> httpClient.patchWithStatus(url, Map.of(), endpoint.getContentType(),
                                endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}");
            case "DELETE" -> httpClient.deleteWithStatus(url, Map.of());
            default       -> httpClient.getWithStatus(url, Map.of());
        };
    }

    private String buildUrl(String baseUrl, String path) {
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        return base + (path.startsWith("/") ? path : "/" + path);
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
                // Only flag when the response looks like a real API/admin response (JSON/XML)
                // AND it differs from what this target returns for a path that doesn't exist.
                // The content-type check alone only screens out HTML catch-alls; an API
                // gateway whose default route answers 200 with a JSON body passes it, and
                // would otherwise yield one CRITICAL finding per admin path probed below.
                // The probe is sent without credentials first, since the finding claims no
                // authorization was needed.
                // Each response is compared with an unknown-path baseline fetched the same way
                // (anonymous or with credentials), so a login wall's sign-in page is not
                // mistaken for an admin endpoint.
                AtomicReference<HttpResponse> anonymousResponse = new AtomicReference<>();
                AnonymousFirstProbe.Result probe = AnonymousFirstProbe.probe(httpClient, testUrl,
                        () -> {
                            HttpResponse r = httpClient.getWithStatusNoAuth(testUrl);
                            anonymousResponse.set(r);
                            return r;
                        },
                        () -> httpClient.getWithStatus(testUrl, Map.of()),
                        r -> r.isSuccess() && isApiResponse(r)
                                && !softNotFoundDetector.looksLikeUnknownPath(cleanBase, httpClient, r, true));
                HttpResponse response = probe.response();

                HttpResponse rejected = anonymousResponse.get();
                if (rejected != null && (rejected.getStatusCode() == 401 || rejected.getStatusCode() == 403)
                        && firstBypassAttempt(httpClient, cleanBase + adminPath)) {
                    Finding bypass = testAccessControlBypass(cleanBase, adminPath, rejected, httpClient);
                    if (bypass != null) {
                        findings.add(bypass);
                    }
                }

                if (response != null && response.isSuccess() && isApiResponse(response)
                        && !softNotFoundDetector.looksLikeUnknownPath(cleanBase, httpClient, response,
                                probe.anonymous())) {
                    Finding finding = probe.anonymous()
                            ? new Finding(
                                    UUID.randomUUID().toString(),
                                    "Administrative Endpoint Accessible Without Authorization",
                                    String.format("The administrative endpoint '%s' returned HTTP %d to a request " +
                                            "sent without any credentials. This could allow unauthorized access " +
                                            "to management functionality.",
                                            adminPath, response.getStatusCode()),
                                    Severity.CRITICAL,
                                    getId(),
                                    "GET " + adminPath,
                                    "Restrict access to administrative endpoints using role-based access control. " +
                                    "Ensure admin endpoints require authentication and appropriate privilege levels. " +
                                    "Consider placing admin interfaces on a separate network or VPN.")
                            : new Finding(
                                    UUID.randomUUID().toString(),
                                    "Administrative Endpoint Accessible" + probe.suffix(),
                                    String.format("The administrative endpoint '%s' rejected a request without " +
                                            "credentials but returned HTTP %d to one sent %s. If the scanning " +
                                            "identity is not meant to have administrative rights, this is a " +
                                            "function-level authorization flaw.",
                                            adminPath, response.getStatusCode(), probe.sentWith()),
                                    Severity.MEDIUM,
                                    getId(),
                                    "GET " + adminPath,
                                    "Confirm the scanning identity's role. Administrative endpoints must check the " +
                                    "caller's privilege level, not only that the caller is authenticated.");
                    finding.setRequestDetails("GET " + testUrl +
                            (probe.anonymous() ? " (no credentials)" : " (" + probe.sentWith() + ")"));
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

    /** @return true the first time {@code key} is seen for this scan's client */
    private boolean firstBypassAttempt(HttpClient httpClient, String key) {
        Set<String> seen;
        synchronized (bypassAttempts) {
            seen = bypassAttempts.computeIfAbsent(httpClient, c -> ConcurrentHashMap.newKeySet());
        }
        return seen.add(key);
    }

    /**
     * Path spellings of {@code adminPath} that a gateway or proxy rule matching the literal path
     * may not recognise while the backend still routes them to the same handler: a doubled
     * leading slash, a trailing slash, the {@code ;} path parameter and {@code ..;} forms that
     * Tomcat and Spring strip, a percent-encoded first character, upper case and a trailing
     * encoded space. Dot-segment forms such as {@code /./admin} and {@code /%2e/admin} are left
     * out because the HTTP client normalises them back to {@code /admin} before sending.
     */
    static List<String> pathBypassVariants(String adminPath) {
        String name = adminPath.substring(1);
        List<String> variants = new ArrayList<>();
        variants.add("/" + adminPath);
        variants.add(adminPath + "/");
        variants.add(adminPath + ";/");
        variants.add(adminPath + "..;/");
        variants.add(String.format("/%%%02X%s", (int) name.charAt(0), name.substring(1)));
        variants.add(adminPath.toUpperCase(Locale.ROOT));
        variants.add(adminPath + "%20");
        return variants;
    }

    /**
     * Runs when an admin path answered a request without credentials with 401 or 403, so the path
     * exists and something protects it. Sends the same anonymous GET through path spellings the
     * protecting rule may not match, and to {@code /} with {@code X-Original-URL} and
     * {@code X-Rewrite-URL} naming the path (honoured by some IIS and Symfony front ends). A
     * variant counts only if it is answered 2xx with an API response that is not the target's
     * unknown-path answer, and for the header forms only if that response also differs from a
     * plain anonymous request to {@code /}.
     *
     * @return a CRITICAL finding for the first variant that gets through, or null
     */
    private Finding testAccessControlBypass(String cleanBase, String adminPath, HttpResponse rejected,
                                            HttpClient httpClient) {
        for (String variant : pathBypassVariants(adminPath)) {
            String url = cleanBase + variant;
            try {
                HttpResponse response = httpClient.getWithStatusNoAuth(url);
                if (bypassAccepted(cleanBase, response, httpClient)) {
                    return bypassFinding(adminPath, "GET " + url, rejected, response,
                            "the path spelled as '" + variant + "'");
                }
            } catch (Exception e) {
                logger.debug("Error testing access control bypass {}: {}", url, e.getMessage());
            }
        }

        String rootUrl = cleanBase + "/";
        HttpResponse root = null;
        try {
            root = httpClient.getWithStatusNoAuth(rootUrl);
        } catch (Exception e) {
            logger.debug("Error fetching {} for the rewrite-header comparison: {}", rootUrl, e.getMessage());
        }
        for (String header : List.of("X-Original-URL", "X-Rewrite-URL")) {
            try {
                HttpResponse response = httpClient.getWithStatusNoAuth(rootUrl, Map.of(header, adminPath));
                if (bypassAccepted(cleanBase, response, httpClient)
                        && (root == null || !root.isSuccess() || !response.getBody().equals(root.getBody()))) {
                    return bypassFinding(adminPath, "GET " + rootUrl + "\n" + header + ": " + adminPath,
                            rejected, response, "a request to '/' with '" + header + ": " + adminPath + "'");
                }
            } catch (Exception e) {
                logger.debug("Error testing {} bypass for {}: {}", header, adminPath, e.getMessage());
            }
        }
        return null;
    }

    private boolean bypassAccepted(String cleanBase, HttpResponse response, HttpClient httpClient) {
        return response != null && response.isSuccess() && isApiResponse(response)
                && !softNotFoundDetector.looksLikeUnknownPath(cleanBase, httpClient, response, true);
    }

    private Finding bypassFinding(String adminPath, String request, HttpResponse rejected, HttpResponse accepted,
                                  String how) {
        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                "Administrative Endpoint Access Control Bypass",
                String.format("The administrative endpoint '%s' answered HTTP %d to a request without " +
                        "credentials, but HTTP %d to %s, also sent without credentials. The rule that " +
                        "protects the endpoint matches the literal path, and the backend serves other " +
                        "spellings of it.", adminPath, rejected.getStatusCode(), accepted.getStatusCode(), how),
                Severity.CRITICAL,
                getId(),
                "GET " + adminPath,
                "Enforce authorization in the application on the route that handles the request, not only " +
                "in a gateway or proxy rule matching the raw path. Normalise paths the same way in every " +
                "layer, reject ';' path parameters and encoded characters in protected paths, and ignore " +
                "X-Original-URL / X-Rewrite-URL from clients."
        );
        finding.setRequestDetails(request + " (no credentials)");
        finding.setResponseDetails("Literal path: HTTP " + rejected.getStatusCode() +
                "\nBypass: HTTP " + accepted.getStatusCode() + "; body length: " + accepted.getBody().length());
        return finding;
    }

    /**
     * Returns true when the response looks like a real API/service response rather than an HTML
     * page. SPAs and reverse proxies typically return HTTP 200 with text/html for every unknown
     * path (client-side routing fallback), which would otherwise produce false positives for
     * admin-path probing and method-escalation checks.
     *
     * <p>Delegates to {@link SoftNotFoundDetector#isApiResponse(HttpResponse)}, which is the
     * single shared copy of a check this class and
     * {@link ImproperInventoryManagementTestCase} previously each carried verbatim. Behaviour is
     * unchanged.</p>
     */
    private boolean isApiResponse(HttpResponse response) {
        return SoftNotFoundDetector.isApiResponse(response);
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
                if (getResponse == null || !getResponse.isSuccess()) {
                    continue;
                }
                // The state-changing request is sent without credentials first, since the
                // finding claims no authorization was needed for it.
                AnonymousFirstProbe.Result probe = AnonymousFirstProbe.probe(httpClient, fullUrl,
                        () -> httpClient.sendWithStatusNoAuth(method, fullUrl, "application/json", "{}"),
                        () -> switch (method) {
                            case "PUT"    -> httpClient.putWithStatus(fullUrl, Map.of(), "application/json", "{}");
                            case "DELETE" -> httpClient.deleteWithStatus(fullUrl, Map.of());
                            case "PATCH"  -> httpClient.patchWithStatus(fullUrl, Map.of(), "application/json", "{}");
                            default       -> null;
                        },
                        r -> r.isSuccess() && isApiResponse(r));
                HttpResponse testResponse = probe.response();

                if (testResponse != null
                        && testResponse.isSuccess()
                        && isApiResponse(testResponse)) {

                    Finding finding = probe.anonymous()
                            ? new Finding(
                                    UUID.randomUUID().toString(),
                                    "HTTP Method Escalation - " + method + " Allowed Without Authorization",
                                    String.format("The endpoint accepted a %s request sent without any credentials. " +
                                            "This could allow unauthorized modification or deletion of resources.",
                                            method),
                                    Severity.HIGH,
                                    getId(),
                                    endpoint.getMethod() + " " + endpoint.getPath(),
                                    "Explicitly validate HTTP method permissions for each endpoint. Do not rely on " +
                                    "route configuration alone. Ensure that state-changing methods (PUT, DELETE, PATCH) " +
                                    "require appropriate authorization even when the GET counterpart is public.")
                            : new Finding(
                                    UUID.randomUUID().toString(),
                                    "HTTP Method Escalation - " + method + " Allowed" + probe.suffix(),
                                    String.format("The endpoint rejected a %s request without credentials but " +
                                            "accepted it when sent %s. If the scanning identity is only meant to " +
                                            "read this resource, it can also modify or delete it.",
                                            method, probe.sentWith()),
                                    Severity.MEDIUM,
                                    getId(),
                                    endpoint.getMethod() + " " + endpoint.getPath(),
                                    "Check that state-changing methods (PUT, DELETE, PATCH) require a privilege " +
                                    "level of their own, not only the one that allows GET.");
                    finding.setRequestDetails(method + " " + fullUrl +
                            (probe.anonymous() ? " (no credentials)" : " (" + probe.sentWith() + ")"));
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
