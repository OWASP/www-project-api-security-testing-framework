package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
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
 * Cross-user BOLA behind an API gateway that requires an application API key in addition to the
 * user's bearer token. The secondary identity's request is first sent with the secondary token
 * only; when that is rejected with 401/403 and the scan has an application credential (the
 * configured API key, or a custom header named like an application key), it is sent again with
 * the secondary token plus that application credential, never the primary token, cookies or
 * other custom headers. Asserted on what reached the server.
 */
@DisplayName("Cross-user BOLA behind an API gateway (wire level)")
class CrossUserBolaGatewayWireTest {

    private static final String OBJECT_PATH = "/api/users/5";
    private static final String CROSS_USER = "Cross-User Access";

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

    private static MockResponse ok() {
        return json(200, "{\"id\":5,\"name\":\"bob\"}");
    }

    private static MockResponse unauthorized() {
        return json(401, "{\"error\":\"unauthorized\"}");
    }

    private static boolean hasBearer(RecordedRequest r) {
        String auth = r.getHeader("Authorization");
        return auth != null && auth.startsWith("Bearer ");
    }

    private static boolean isSecondary(RecordedRequest r) {
        return "Bearer secondary-token".equals(r.getHeader("Authorization"));
    }

    /** Starts a server; {@code objectHandler} answers requests for the object path. */
    private HttpClient start(ScanConfig config, Function<RecordedRequest, MockResponse> objectHandler)
            throws Exception {
        server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                String path = request.getPath() == null ? "" : request.getPath();
                if (path.startsWith("/session-cookie")) {
                    return new MockResponse().setResponseCode(200)
                            .addHeader("Set-Cookie", "sid=primary-cookie; Path=/");
                }
                if (path.startsWith("/api/users/")) {
                    return objectHandler.apply(request);
                }
                return json(404, "");
            }
        });
        server.start();
        config.setTargetUrl(server.url("/").toString());
        config.setSecondaryBearerToken("secondary-token");
        HttpClient client = new HttpClient(config);
        client.getWithStatus(server.url("/session-cookie").toString(), Map.of());
        received.clear();
        return client;
    }

    /** A config as the CLI builds it for --token plus --api-key, plus a user-identity custom header. */
    private static ScanConfig gatewayConfig() {
        ScanConfig config = new ScanConfig();
        config.setBearerToken("primary-token");
        config.setApiKey("app-key");
        config.setApiKeyHeader("X-API-Key");
        config.addHeader("X-API-Key", "app-key");
        config.addHeader("X-Session-Token", "custom-secret");
        return config;
    }

    private EndpointInfo endpoint() {
        EndpointInfo e = new EndpointInfo(OBJECT_PATH, "GET", "application/json", null, true);
        String url = server.url("/").toString();
        e.setBaseUrl(url.substring(0, url.length() - 1));
        return e;
    }

    private List<RecordedRequest> objectRequests() {
        return received.stream().filter(r -> OBJECT_PATH.equals(r.getPath())).collect(Collectors.toList());
    }

    private static String titles(List<Finding> findings) {
        return findings.stream().map(f -> f.getTitle() + " [" + f.getSeverity() + "]")
                .collect(Collectors.joining("; "));
    }

    private static Finding crossUser(List<Finding> findings) {
        List<Finding> matching = findings.stream().filter(f -> f.getTitle().contains(CROSS_USER)).toList();
        assertEquals(1, matching.size(), titles(findings));
        return matching.get(0);
    }

    private static String evidence(Finding f) {
        return f.getRequestDetails() + "\n" + f.getResponseDetails();
    }

    /** Nothing of the primary identity other than the application credential may be on the request. */
    private static void assertNoPrimaryIdentity(RecordedRequest r) {
        assertFalse(r.getHeaders().toString().contains("primary-token"),
                "primary bearer token was sent: " + r.getHeaders());
        assertNull(r.getHeader("Cookie"), "primary cookie was sent: " + r.getRequestLine());
        assertNull(r.getHeader("X-Session-Token"), "primary custom header was sent: " + r.getRequestLine());
    }

    @Test
    @DisplayName("Gateway needing x-api-key + bearer: retried with secondary bearer + API key, finding produced")
    void gatewayRequiringApiKeyAndBearer() throws Exception {
        HttpClient client = start(gatewayConfig(),
                r -> "app-key".equals(r.getHeader("X-API-Key")) && hasBearer(r) ? ok() : unauthorized());

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase().execute(endpoint(), client);

        Finding f = crossUser(findings);
        assertEquals(Severity.CRITICAL, f.getSeverity());
        assertTrue(f.getTitle().contains("application API key"), f.getTitle());
        assertTrue(evidence(f).contains("secondary token plus the application credential X-API-Key"), evidence(f));
        assertTrue(evidence(f).contains("Secondary identity status (secondary token only): 401"), evidence(f));

        List<RecordedRequest> secondary = objectRequests().stream()
                .filter(CrossUserBolaGatewayWireTest::isSecondary).toList();
        assertEquals(2, secondary.size(), "bare secondary request, then one retry with the API key");
        assertNull(secondary.get(0).getHeader("X-API-Key"), "the first secondary request carries the secondary token only");
        assertEquals("app-key", secondary.get(1).getHeader("X-API-Key"));
        secondary.forEach(CrossUserBolaGatewayWireTest::assertNoPrimaryIdentity);

        // The control request (API key alone, no bearer) carries no user identity at all.
        List<RecordedRequest> control = objectRequests().stream()
                .filter(r -> r.getHeader("Authorization") == null).toList();
        assertEquals(1, control.size());
        assertEquals("app-key", control.get(0).getHeader("X-API-Key"));
        assertNoPrimaryIdentity(control.get(0));
    }

    @Test
    @DisplayName("Gateway that also accepts the API key alone: reported at MEDIUM, saying the key alone was accepted")
    void gatewayAcceptingApiKeyAlone() throws Exception {
        HttpClient client = start(gatewayConfig(),
                r -> "app-key".equals(r.getHeader("X-API-Key")) ? ok() : unauthorized());

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase().execute(endpoint(), client);

        Finding f = crossUser(findings);
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertTrue(f.getTitle().contains("application API key alone also accepted"), f.getTitle());
        assertTrue(evidence(f).contains("Application credential only (no bearer token) status: 200"), evidence(f));
    }

    @Test
    @DisplayName("Gateway that enforces object ownership: secondary rejected even with the API key, no finding")
    void gatewayEnforcingOwnership() throws Exception {
        HttpClient client = start(gatewayConfig(),
                r -> "app-key".equals(r.getHeader("X-API-Key")) && "Bearer primary-token".equals(r.getHeader("Authorization"))
                        ? ok() : json(403, "{}"));

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase().execute(endpoint(), client);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains(CROSS_USER)), titles(findings));
        List<RecordedRequest> secondary = objectRequests().stream()
                .filter(CrossUserBolaGatewayWireTest::isSecondary).toList();
        assertEquals(2, secondary.size(), "the retry with the API key was still attempted");
        secondary.forEach(CrossUserBolaGatewayWireTest::assertNoPrimaryIdentity);
    }

    @Test
    @DisplayName("Application key in a custom header (no --api-key) is used for the retry; identity headers are not")
    void customApplicationKeyHeader() throws Exception {
        ScanConfig config = new ScanConfig();
        config.setBearerToken("primary-token");
        config.addHeader("Ocp-Apim-Subscription-Key", "sub-key");
        config.addHeader("X-User-Id", "primary-user");
        HttpClient client = start(config,
                r -> "sub-key".equals(r.getHeader("Ocp-Apim-Subscription-Key")) && hasBearer(r) ? ok() : unauthorized());

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase().execute(endpoint(), client);

        Finding f = crossUser(findings);
        assertEquals(Severity.CRITICAL, f.getSeverity());
        assertTrue(evidence(f).contains("Ocp-Apim-Subscription-Key"), evidence(f));
        List<RecordedRequest> secondary = objectRequests().stream()
                .filter(CrossUserBolaGatewayWireTest::isSecondary).toList();
        assertEquals(2, secondary.size());
        assertEquals("sub-key", secondary.get(1).getHeader("Ocp-Apim-Subscription-Key"));
        for (RecordedRequest r : secondary) {
            assertNoPrimaryIdentity(r);
            assertNull(r.getHeader("X-User-Id"), "user identity header was sent on the secondary request");
        }
    }

    @Test
    @DisplayName("Plain bearer API: secondary request carries the secondary token only, no API key, finding as before")
    void plainBearerApi() throws Exception {
        ScanConfig config = new ScanConfig();
        config.setBearerToken("primary-token");
        HttpClient client = start(config, r -> hasBearer(r) ? ok() : unauthorized());

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase().execute(endpoint(), client);

        Finding f = crossUser(findings);
        assertEquals(Severity.CRITICAL, f.getSeverity());
        assertEquals("Broken Object Level Authorization (Cross-User Access Confirmed)", f.getTitle());
        assertTrue(evidence(f).contains("the secondary token alone"), evidence(f));
        List<RecordedRequest> secondary = objectRequests().stream()
                .filter(CrossUserBolaGatewayWireTest::isSecondary).toList();
        assertEquals(1, secondary.size());
        assertNull(secondary.get(0).getHeader("X-API-Key"));
        received.forEach(r -> assertNull(r.getHeader("X-API-Key"), "an API key was sent: " + r.getRequestLine()));
    }

    @Test
    @DisplayName("Secondary token rejected and no application credential configured: no retry, no finding")
    void rejectedWithoutApplicationCredential() throws Exception {
        ScanConfig config = new ScanConfig();
        config.setBearerToken("primary-token");
        config.addHeader("X-Session-Token", "custom-secret");
        HttpClient client = start(config,
                r -> "Bearer primary-token".equals(r.getHeader("Authorization")) ? ok() : json(403, "{}"));

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase().execute(endpoint(), client);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains(CROSS_USER)), titles(findings));
        List<RecordedRequest> secondary = objectRequests().stream()
                .filter(CrossUserBolaGatewayWireTest::isSecondary).toList();
        assertEquals(1, secondary.size());
        assertNoPrimaryIdentity(secondary.get(0));
        assertNull(secondary.get(0).getHeader("X-API-Key"));
    }
}
