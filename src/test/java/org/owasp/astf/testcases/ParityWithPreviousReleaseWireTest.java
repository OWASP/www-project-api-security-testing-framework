package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 2.1.0 sends stricter requests first (no custom headers for an unauthenticated probe, the secondary
 * token alone for cross-user access). An API gateway that needs a routing or subscription header on
 * every request rejects those, so each check then falls back to the request 2.0.2 sent. These tests
 * run a gateway that only answers requests carrying {@code X-Gateway-Route} and prove 2.1.0 still
 * finds what 2.0.2 found there, saying in the finding what was sent.
 */
@DisplayName("2.1.0 finds what 2.0.2 found behind a gateway that needs a custom header")
class ParityWithPreviousReleaseWireTest {

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

    private HttpClient start(ScanConfig config, Function<RecordedRequest, MockResponse> handler) throws Exception {
        server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                return handler.apply(request);
            }
        });
        server.start();
        config.setTargetUrl(server.url("/").toString());
        return new HttpClient(config);
    }

    private EndpointInfo endpoint(String path, String method) {
        EndpointInfo e = new EndpointInfo(path, method, "application/json", null, true);
        String url = server.url("/").toString();
        e.setBaseUrl(url.substring(0, url.length() - 1));
        return e;
    }

    private static ScanConfig gatewayConfig() {
        ScanConfig config = new ScanConfig();
        config.setBearerToken("primary-token");
        config.addHeader("X-Gateway-Route", "shared-route");
        return config;
    }

    @Test
    @DisplayName("Missing authentication: rejected without the custom header, accepted with it and no Authorization")
    void missingAuthenticationFallsBackToCustomHeadersKept() throws Exception {
        // The gateway answers only requests that carry its routing header; the API behind it checks nothing else.
        HttpClient client = start(gatewayConfig(), r ->
                r.getHeader("X-Gateway-Route") != null ? json(200, "{\"items\":[1,2,3]}") : json(401, "{\"error\":\"no route\"}"));

        List<Finding> findings = new BrokenAuthenticationTestCase().execute(endpoint("/api/items", "GET"), client);

        Finding missing = findings.stream().filter(f -> f.getTitle().equals("Missing Authentication Controls"))
                .findFirst().orElse(null);
        assertTrue(missing != null, "the 2.0.2 finding must still be produced");
        assertTrue(missing.getEvidence().contains("X-Gateway-Route"), missing.getEvidence());
        assertTrue(received.stream().anyMatch(r -> r.getHeader("X-Gateway-Route") != null
                && r.getHeader("Authorization") == null),
                "the fallback request carries the custom header and no Authorization");
        assertTrue(received.stream().noneMatch(r -> "/api/items".equals(r.getPath())
                && r.getHeader("Authorization") != null && r.getHeader("X-Gateway-Route") == null),
                "no request mixes identity back in");
    }

    @Test
    @DisplayName("Missing authentication: a gateway that needs the custom header AND a valid token gives no finding")
    void missingAuthenticationNotReportedWhenTokenIsRequired() throws Exception {
        HttpClient client = start(gatewayConfig(), r ->
                r.getHeader("X-Gateway-Route") != null && r.getHeader("Authorization") != null
                        ? json(200, "{\"items\":[1]}") : json(401, "{\"error\":\"unauthorized\"}"));

        List<Finding> findings = new BrokenAuthenticationTestCase().execute(endpoint("/api/items", "GET"), client);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().equals("Missing Authentication Controls")),
                "an endpoint that checks the token must not be reported as missing authentication");
    }

    @Test
    @DisplayName("Cross-user access: secondary token alone rejected, 2.0.2 form accepted gives a HIGH finding")
    void crossUserFallsBackToOnlyAuthorizationReplaced() throws Exception {
        ScanConfig config = gatewayConfig();
        config.setSecondaryBearerToken("secondary-token");
        // Needs the routing header on every request; does not look at which user asks.
        HttpClient client = start(config, r ->
                r.getHeader("X-Gateway-Route") != null && r.getHeader("Authorization") != null
                        ? json(200, "{\"id\":5,\"name\":\"bob\"}") : json(401, "{\"error\":\"no route\"}"));

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase()
                .execute(endpoint("/api/users/5", "GET"), client);

        Finding cross = findings.stream().filter(f -> f.getTitle().contains("Cross-User Access")).findFirst().orElse(null);
        assertTrue(cross != null, "the 2.0.2 cross-user finding must still be produced");
        assertEquals(Severity.HIGH, cross.getSeverity(), "other headers rode along, so it is not CRITICAL");
        assertTrue(cross.getTitle().contains("other configured headers kept"), cross.getTitle());
        assertTrue(cross.getRequestDetails().contains("X-Gateway-Route"), cross.getRequestDetails());
        assertTrue(received.stream().noneMatch(r -> "Bearer secondary-token".equals(r.getHeader("Authorization"))
                && "Bearer primary-token".equals(r.getHeader("Authorization"))));
    }

    @Test
    @DisplayName("Cross-user access: an API that rejects the secondary token even with the headers gives no finding")
    void crossUserNotReportedWhenSecondaryTokenIsRejectedEverywhere() throws Exception {
        ScanConfig config = gatewayConfig();
        config.setSecondaryBearerToken("secondary-token");
        HttpClient client = start(config, r ->
                "Bearer primary-token".equals(r.getHeader("Authorization")) && r.getHeader("X-Gateway-Route") != null
                        ? json(200, "{\"id\":5}") : json(403, "{\"error\":\"forbidden\"}"));

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase()
                .execute(endpoint("/api/users/5", "GET"), client);

        assertFalse(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access")),
                "access that only works for the primary user is not a cross-user finding");
    }

    @Test
    @DisplayName("Plain bearer API: nothing extra is sent and the strict CRITICAL finding is unchanged")
    void plainApiKeepsTheStrictCriticalFinding() throws Exception {
        ScanConfig config = new ScanConfig();
        config.setBearerToken("primary-token");
        config.setSecondaryBearerToken("secondary-token");
        HttpClient client = start(config, r -> r.getHeader("Authorization") != null
                ? json(200, "{\"id\":5}") : json(401, "{}"));

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase()
                .execute(endpoint("/api/users/5", "GET"), client);

        Finding cross = findings.stream().filter(f -> f.getTitle().contains("Cross-User Access")).findFirst().orElse(null);
        assertTrue(cross != null);
        assertEquals(Severity.CRITICAL, cross.getSeverity());
        assertEquals("Broken Object Level Authorization (Cross-User Access Confirmed)", cross.getTitle());
    }

    @Test
    @DisplayName("Debug endpoint behind a gateway that needs the custom header is still reported, labelled with the headers, never as public")
    void debugEndpointBehindGatewayIsStillReportedAndLabelled() throws Exception {
        ScanConfig config = new ScanConfig();
        config.addHeader("X-Gateway-Route", "shared-route");           // no token, key or cookie: only a routing header
        HttpClient client = start(config, r -> {
            if (r.getHeader("X-Gateway-Route") == null) {
                return json(401, "{\"error\":\"no route\"}");
            }
            return "/actuator/env".equals(r.getPath())
                    ? json(200, "{\"activeProfiles\":[\"prod\"],\"propertySources\":[{\"name\":\"systemEnvironment\"}]}")
                    : json(404, "{\"error\":\"not found\"}");
        });
        EndpointInfo root = endpoint("/", "GET");

        List<Finding> findings = new SecurityMisconfigurationTestCase().execute(root, client);

        Finding debug = findings.stream()
                .filter(f -> f.getTitle().startsWith("Debug/Diagnostic Endpoint Exposed")
                        && f.getDescription().contains("/actuator/env"))
                .findFirst().orElse(null);
        assertTrue(debug != null, "2.0.2 reported this endpoint, so 2.1.0 must too");
        assertTrue(debug.getTitle().endsWith("(reachable with the configured headers)"), debug.getTitle());
        assertTrue(findings.stream().noneMatch(f -> f.getTitle().equals("Debug/Diagnostic Endpoint Exposed")
                && f.getDescription().contains("/actuator/env")), "it must not be claimed as public");
        assertTrue(received.stream().anyMatch(r -> "/actuator/env".equals(r.getPath())
                && r.getHeader("X-Gateway-Route") == null), "the strict anonymous request was sent first");
    }
}
