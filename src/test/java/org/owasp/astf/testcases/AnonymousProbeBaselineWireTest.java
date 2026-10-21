package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Anonymous probes are judged against what the target says to an anonymous caller: the soft-404
 * baseline for an anonymous probe is fetched anonymously, and the brute-force lockout check does
 * not read a gateway's blanket rejection of anonymous calls as "no lockout".
 */
@DisplayName("Anonymous probes use anonymous baselines (wire level)")
class AnonymousProbeBaselineWireTest {

    private static final String PHRASE = "reachable with the configured credentials";
    private static final String LOGIN_WALL = "{\"message\":\"Please sign in to continue\",\"signInUrl\":\"/sso/start\"}";

    private MockWebServer server;
    private final List<RecordedRequest> received = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws IOException {
        if (server != null) {
            server.shutdown();
        }
    }

    private static MockResponse json(int code, String body) {
        return new MockResponse().setResponseCode(code)
                .setHeader("Content-Type", "application/json").setBody(body);
    }

    private static boolean authed(RecordedRequest r) {
        return "Bearer primary-token".equals(r.getHeader("Authorization"));
    }

    private HttpClient start(boolean withCredentials, BiFunction<RecordedRequest, String, MockResponse> handler)
            throws Exception {
        server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                String path = request.getPath() == null ? "" : request.getPath();
                MockResponse r = handler.apply(request, path);
                return r != null ? r : new MockResponse().setResponseCode(404).setBody("");
            }
        });
        server.start();
        ScanConfig config = new ScanConfig();
        config.setTargetUrl(server.url("/").toString());
        if (withCredentials) {
            config.setBearerToken("primary-token");
        }
        return new HttpClient(config);
    }

    /**
     * A target behind a login wall: every anonymous request gets the same 200 JSON sign-in page;
     * authenticated requests reach the app, which 404s unknown paths. {@code realAnonymous} names
     * one path that really is served to anonymous callers.
     */
    private BiFunction<RecordedRequest, String, MockResponse> loginWall(String realAnonymous, String realBody) {
        return (r, path) -> {
            if (path.equals(realAnonymous)) return json(200, realBody);
            if (!authed(r)) return json(200, LOGIN_WALL);
            return null;
        };
    }

    private String base() {
        String url = server.url("/").toString();
        return url.substring(0, url.length() - 1);
    }

    private EndpointInfo endpoint(String path, String method) {
        EndpointInfo e = new EndpointInfo(path, method, "application/json", null, false);
        e.setBaseUrl(base());
        return e;
    }

    private static String titles(List<Finding> findings) {
        return findings.stream().map(f -> f.getTitle() + " [" + f.getSeverity() + "]")
                .collect(Collectors.joining("; "));
    }

    private List<RecordedRequest> unknownPathProbes() {
        return received.stream().filter(r -> r.getPath() != null && r.getPath().contains("astf-unknown-path-probe"))
                .collect(Collectors.toList());
    }

    // ── (1) anonymous soft-404 baseline ────────────────────────────────────

    @Test
    @DisplayName("Debug probe behind a login wall: the sign-in page is not reported as an exposed debug endpoint")
    void debugProbeBehindLoginWall() throws Exception {
        HttpClient client = start(true, loginWall("/actuator/env", "{\"activeProfiles\":[\"prod\"],\"propertySources\":[]}"));

        List<Finding> findings = new SecurityMisconfigurationTestCase().execute(endpoint("/", "GET"), client);

        List<Finding> debug = findings.stream().filter(f -> f.getTitle().contains("Debug/Diagnostic")).toList();
        assertEquals(1, debug.size(), "only the real anonymous debug endpoint may be reported: " + titles(findings));
        assertEquals("Debug/Diagnostic Endpoint Exposed", debug.get(0).getTitle());
        assertEquals("GET /actuator/env", debug.get(0).getEndpoint());
        assertEquals(Severity.HIGH, debug.get(0).getSeverity());
        assertTrue(unknownPathProbes().stream().anyMatch(r -> r.getHeader("Authorization") == null),
                "an anonymous unknown-path baseline must have been fetched");
    }

    @Test
    @DisplayName("BFLA admin probe behind a login wall: the sign-in page is not reported as an admin endpoint")
    void adminProbeBehindLoginWall() throws Exception {
        HttpClient client = start(true, loginWall("/admin", "{\"users\":[{\"id\":1,\"role\":\"admin\"}]}"));

        List<Finding> findings = new BrokenFunctionLevelAuthorizationTestCase()
                .execute(endpoint("/api/items", "GET"), client);

        List<Finding> admin = findings.stream().filter(f -> f.getTitle().contains("Administrative Endpoint")).toList();
        assertEquals(1, admin.size(), "only the real anonymous admin endpoint may be reported: " + titles(findings));
        assertEquals("Administrative Endpoint Accessible Without Authorization", admin.get(0).getTitle());
        assertTrue(admin.get(0).getRequestDetails().contains("/admin "), admin.get(0).getRequestDetails());
        assertTrue(unknownPathProbes().stream().anyMatch(r -> r.getHeader("Authorization") == null),
                "an anonymous unknown-path baseline must have been fetched");
    }

    @Test
    @DisplayName("Credentialed retries are still compared with the credentialed baseline")
    void credentialedRetryUsesCredentialedBaseline() throws Exception {
        // Anonymous callers get a 401; authenticated callers get a catch-all 200 JSON page for
        // every unknown path, and a real debug endpoint at /actuator/env.
        HttpClient client = start(true, (r, path) -> {
            if (!authed(r)) return json(401, "{\"error\":\"unauthorized\"}");
            if (path.equals("/actuator/env")) return json(200, "{\"activeProfiles\":[\"prod\"],\"propertySources\":[]}");
            return json(200, "{\"app\":\"shell\",\"version\":\"1\"}");
        });

        List<Finding> findings = new SecurityMisconfigurationTestCase().execute(endpoint("/", "GET"), client);

        List<Finding> debug = findings.stream().filter(f -> f.getTitle().contains("Debug/Diagnostic")).toList();
        assertEquals(1, debug.size(), titles(findings));
        assertTrue(debug.get(0).getTitle().contains(PHRASE), debug.get(0).getTitle());
        assertEquals("GET /actuator/env", debug.get(0).getEndpoint());
        assertTrue(unknownPathProbes().stream().anyMatch(AnonymousProbeBaselineWireTest::authed),
                "a credentialed unknown-path baseline must have been fetched for the credentialed retry");
    }

    @Test
    @DisplayName("Documentation probe behind a login wall: the sign-in page is not reported as documentation")
    void docsProbeBehindLoginWall() throws Exception {
        HttpClient client = start(true, loginWall("/openapi.json", "{\"openapi\":\"3.0.0\",\"paths\":{}}"));

        List<Finding> findings = new ImproperInventoryManagementTestCase().execute(endpoint("/", "GET"), client);

        List<Finding> docs = findings.stream().filter(f -> f.getTitle().contains("API Documentation")).toList();
        assertEquals(1, docs.size(), titles(findings));
        assertEquals("API Documentation Publicly Exposed", docs.get(0).getTitle());
        assertEquals("GET /openapi.json", docs.get(0).getEndpoint());
    }

    // ── (2) brute-force lockout ────────────────────────────────────────────

    private static final String LOGIN = "/api/login";

    private static String lockoutTitle() {
        return "No Account Lockout or Rate Limiting on Repeated Failed Logins";
    }

    private List<RecordedRequest> loginRequests() {
        return received.stream().filter(r -> LOGIN.equals(r.getPath())).collect(Collectors.toList());
    }

    @Test
    @DisplayName("Lockout: a gateway rejecting anonymous calls is not missing lockout; retried with credentials and labelled")
    void lockoutGatewayRejectsAnonymousRetriesWithCredentials() throws Exception {
        HttpClient client = start(true, (r, path) -> {
            if (!authed(r)) return json(401, "{\"error\":\"missing token\"}");
            if (path.equals(LOGIN)) return json(401, "{\"error\":\"invalid username or password\"}");
            return null;
        });

        List<Finding> findings = new BrokenAuthenticationTestCase().testBruteForceLockout(endpoint(LOGIN, "POST"), client);

        assertEquals(1, findings.size(), titles(findings));
        Finding f = findings.get(0);
        assertEquals(lockoutTitle() + AnonymousFirstProbe.CREDENTIALED_SUFFIX, f.getTitle());
        assertEquals(Severity.LOW, f.getSeverity());
        assertTrue(f.getEvidence().contains("with the configured credentials"), f.getEvidence());
        assertNull(loginRequests().get(0).getHeader("Authorization"), "the first attempts are anonymous");
        assertTrue(loginRequests().stream().anyMatch(AnonymousProbeBaselineWireTest::authed),
                "the attempts must be repeated with the configured credentials");
    }

    @Test
    @DisplayName("Lockout: with no credentials, attempts a gateway rejected are reported at LOW as not confirmed, as 2.0.2 reported them")
    void lockoutGatewayRejectsAnonymousNoCredentials() throws Exception {
        HttpClient client = start(false, (r, path) -> json(401, "{\"error\":\"missing token\"}"));

        List<Finding> findings = new BrokenAuthenticationTestCase().testBruteForceLockout(endpoint(LOGIN, "POST"), client);

        assertEquals(1, findings.size(), titles(findings));
        assertEquals(lockoutTitle() + " (not confirmed)", findings.get(0).getTitle());
        assertEquals(Severity.LOW, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getDescription().contains("may have been rejected"), findings.get(0).getDescription());
        assertFalse(loginRequests().isEmpty(), "the attempts must still be sent");
    }

    @Test
    @DisplayName("Lockout: a login handler that answers 401 for a wrong password is still reported (anonymous)")
    void lockoutHandlerAnswers401StillReported() throws Exception {
        HttpClient client = start(false, (r, path) ->
                path.equals(LOGIN) ? json(401, "{\"error\":\"invalid username or password\"}") : null);

        List<Finding> findings = new BrokenAuthenticationTestCase().testBruteForceLockout(endpoint(LOGIN, "POST"), client);

        assertEquals(1, findings.size(), titles(findings));
        assertEquals(lockoutTitle(), findings.get(0).getTitle());
        assertEquals(Severity.MEDIUM, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getEvidence().contains("without credentials"), findings.get(0).getEvidence());
    }

    @Test
    @DisplayName("Lockout: credentials that the gateway also rejects give a LOW not-confirmed finding, not a MEDIUM one")
    void lockoutGatewayRejectsCredentialsToo() throws Exception {
        HttpClient client = start(true, (r, path) -> json(403, "{\"error\":\"forbidden\"}"));

        List<Finding> findings = new BrokenAuthenticationTestCase().testBruteForceLockout(endpoint(LOGIN, "POST"), client);

        assertEquals(1, findings.size(), titles(findings));
        assertEquals(Severity.LOW, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getTitle().endsWith("(not confirmed)"), findings.get(0).getTitle());
        assertTrue(loginRequests().stream().anyMatch(AnonymousProbeBaselineWireTest::authed),
                "the credentialed attempts must still have been sent");
    }

    @Test
    @DisplayName("Lockout: a credentialed run that hits a 429 reports nothing")
    void lockoutCredentialedRateLimited() throws Exception {
        int[] authedAttempts = {0};
        HttpClient client = start(true, (r, path) -> {
            if (!authed(r)) return json(401, "{\"error\":\"missing token\"}");
            if (path.equals(LOGIN)) {
                return ++authedAttempts[0] >= 3 ? json(429, "{\"error\":\"slow down\"}")
                        : json(401, "{\"error\":\"invalid username or password\"}");
            }
            return null;
        });

        List<Finding> findings = new BrokenAuthenticationTestCase().testBruteForceLockout(endpoint(LOGIN, "POST"), client);

        assertTrue(findings.isEmpty(), titles(findings));
    }
}
