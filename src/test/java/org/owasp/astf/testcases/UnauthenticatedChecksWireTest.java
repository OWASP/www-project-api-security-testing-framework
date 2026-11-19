package org.owasp.astf.testcases;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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
 * Checks that claim "without authorization", "publicly accessible" or an anonymous attacker
 * really send their probes without the scan's credentials (asserted on what reached the server),
 * and that a result only reachable with the scan's credentials says so at a lower severity
 * instead of claiming no authentication.
 */
@DisplayName("Unauthenticated checks send no credentials (wire level)")
class UnauthenticatedChecksWireTest {

    private static final String PHRASE = "reachable with the configured credentials";

    private MockWebServer server;
    private final List<RecordedRequest> received = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws IOException {
        if (server != null) {
            server.shutdown();
        }
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private static MockResponse json(int code, String body) {
        return new MockResponse().setResponseCode(code)
                .setHeader("Content-Type", "application/json").setBody(body);
    }

    private static MockResponse notFound() {
        return new MockResponse().setResponseCode(404).setBody("");
    }

    /** True when the request carries the primary identity's bearer token. */
    private static boolean authed(RecordedRequest r) {
        return "Bearer primary-token".equals(r.getHeader("Authorization"));
    }

    /**
     * Starts a server whose behaviour per request is given by {@code handler}; a path the
     * handler answers with {@code null} gets a 404. The returned client has a bearer token, an
     * API key, a credential-like custom header and a captured session cookie.
     */
    private HttpClient start(BiFunction<RecordedRequest, String, MockResponse> handler) throws Exception {
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
                MockResponse r = handler.apply(request, path);
                return r != null ? r : notFound();
            }
        });
        server.start();
        HttpClient client = new HttpClient(credentialedConfig(server.url("/").toString()));
        client.getWithStatus(server.url("/session-cookie").toString(), Map.of());
        received.clear();
        return client;
    }

    private static ScanConfig credentialedConfig(String target) {
        ScanConfig config = new ScanConfig();
        config.setTargetUrl(target);
        config.setBearerToken("primary-token");
        config.setApiKey("primary-key");
        config.setApiKeyHeader("X-API-Key");
        config.addHeader("X-API-Key", "primary-key");
        config.addHeader("X-Session-Token", "custom-secret");
        return config;
    }

    private String base() {
        String url = server.url("/").toString();
        return url.substring(0, url.length() - 1);
    }

    private EndpointInfo endpoint(String path, String method) {
        return endpoint(path, method, null, false);
    }

    private EndpointInfo endpoint(String path, String method, String body, boolean requiresAuth) {
        EndpointInfo e = new EndpointInfo(path, method, "application/json", body, requiresAuth);
        e.setBaseUrl(base());
        return e;
    }

    private List<RecordedRequest> requestsTo(String path) {
        return received.stream().filter(r -> path.equals(r.getPath())).collect(Collectors.toList());
    }

    private static void assertNoCredentials(RecordedRequest r) {
        assertNull(r.getHeader("Authorization"), "Authorization was sent: " + r.getRequestLine());
        assertNull(r.getHeader("X-API-Key"), "API key was sent: " + r.getRequestLine());
        assertNull(r.getHeader("X-Session-Token"), "custom credential header was sent: " + r.getRequestLine());
        assertNull(r.getHeader("Cookie"), "cookie was sent: " + r.getRequestLine());
    }

    private static String titles(List<Finding> findings) {
        return findings.stream().map(f -> f.getTitle() + " [" + f.getSeverity() + "]")
                .collect(Collectors.joining("; "));
    }

    private static Finding only(List<Finding> findings, String titleFragment) {
        List<Finding> matching = findings.stream().filter(f -> f.getTitle().contains(titleFragment)).toList();
        assertEquals(1, matching.size(), "expected one finding containing '" + titleFragment + "', got " + titles(findings));
        return matching.get(0);
    }

    // ── BFLA: admin paths ──────────────────────────────────────────────────

    @Test
    @DisplayName("BFLA admin probe: first request carries no credentials; a public admin path is CRITICAL")
    void bflaAdminPublic() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/admin") ? json(200, "{\"users\":[1,2]}") : null);

        List<Finding> findings = new BrokenFunctionLevelAuthorizationTestCase().execute(endpoint("/api/items", "GET"), client);

        Finding f = only(findings, "Administrative Endpoint");
        assertEquals("Administrative Endpoint Accessible Without Authorization", f.getTitle());
        assertEquals(Severity.CRITICAL, f.getSeverity());
        requestsTo("/admin").forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("BFLA admin probe: an admin path that needs the scan's token is reported as reachable with credentials")
    void bflaAdminNeedsCredentials() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/admin")
                ? (authed(r) ? json(200, "{\"users\":[1,2]}") : json(401, "{\"error\":\"unauthorized\"}"))
                : null);

        List<Finding> findings = new BrokenFunctionLevelAuthorizationTestCase().execute(endpoint("/api/items", "GET"), client);

        assertFalse(findings.stream().anyMatch(f -> f.getTitle().contains("Without Authorization")), titles(findings));
        Finding f = only(findings, "Administrative Endpoint");
        assertTrue(f.getTitle().contains(PHRASE), f.getTitle());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertNoCredentials(requestsTo("/admin").get(0));
    }

    // ── BFLA: HTTP method escalation ───────────────────────────────────────

    @Test
    @DisplayName("BFLA method escalation: PUT/PATCH/DELETE accepted anonymously is HIGH, probes carry no credentials")
    void bflaMethodPublic() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/api/items/1") ? json(200, "{\"id\":1}") : null);

        List<Finding> findings = new BrokenFunctionLevelAuthorizationTestCase().execute(endpoint("/api/items/1", "GET"), client);

        Finding put = only(findings, "PUT Allowed");
        assertEquals("HTTP Method Escalation - PUT Allowed Without Authorization", put.getTitle());
        assertEquals(Severity.HIGH, put.getSeverity());
        received.stream().filter(r -> "/api/items/1".equals(r.getPath()) && !"GET".equals(r.getMethod()))
                .forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("BFLA method escalation: methods that need the scan's token are reported as reachable with credentials")
    void bflaMethodNeedsCredentials() throws Exception {
        HttpClient client = start((r, path) -> {
            if (!path.equals("/api/items/1")) return null;
            if (r.getMethod().equals("GET") || authed(r)) return json(200, "{\"id\":1}");
            return json(401, "{\"error\":\"unauthorized\"}");
        });

        List<Finding> findings = new BrokenFunctionLevelAuthorizationTestCase().execute(endpoint("/api/items/1", "GET"), client);

        assertFalse(findings.stream().anyMatch(f -> f.getTitle().contains("Without Authorization")), titles(findings));
        Finding put = only(findings, "PUT Allowed");
        assertTrue(put.getTitle().contains(PHRASE), put.getTitle());
        assertEquals(Severity.MEDIUM, put.getSeverity());
        RecordedRequest firstPut = received.stream()
                .filter(r -> "/api/items/1".equals(r.getPath()) && "PUT".equals(r.getMethod())).findFirst().orElseThrow();
        assertNoCredentials(firstPut);
    }

    // ── Security misconfiguration: debug endpoints ─────────────────────────

    @Test
    @DisplayName("Debug endpoint probe carries no credentials; a public one is HIGH")
    void debugEndpointPublic() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/actuator/env") ? json(200, "{\"activeProfiles\":[]}") : null);

        List<Finding> findings = new SecurityMisconfigurationTestCase().execute(endpoint("/", "GET"), client);

        Finding f = only(findings, "Debug/Diagnostic Endpoint");
        assertEquals("Debug/Diagnostic Endpoint Exposed", f.getTitle());
        assertEquals(Severity.HIGH, f.getSeverity());
        requestsTo("/actuator/env").forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("Debug endpoint that needs the scan's token is reported as reachable with credentials")
    void debugEndpointNeedsCredentials() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/actuator/env")
                ? (authed(r) ? json(200, "{\"activeProfiles\":[]}") : json(401, "{\"error\":\"unauthorized\"}"))
                : null);

        List<Finding> findings = new SecurityMisconfigurationTestCase().execute(endpoint("/", "GET"), client);

        Finding f = only(findings, "Debug/Diagnostic Endpoint");
        assertTrue(f.getTitle().contains(PHRASE), f.getTitle());
        assertFalse(f.getDescription().contains("publicly accessible"), f.getDescription());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertNoCredentials(requestsTo("/actuator/env").get(0));
    }

    // ── Improper inventory: shadow endpoints and documentation ─────────────

    @Test
    @DisplayName("Shadow endpoint probe carries no credentials; a public one is HIGH")
    void shadowPublic() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/api/beta/items") ? json(200, "[{\"id\":1}]") : null);

        List<Finding> findings = new ImproperInventoryManagementTestCase().execute(endpoint("/api/v2/items", "GET"), client);

        Finding f = only(findings, "Shadow/Non-Production");
        assertEquals("Shadow/Non-Production API Endpoint Accessible", f.getTitle());
        assertEquals(Severity.HIGH, f.getSeverity());
        requestsTo("/api/beta/items").forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("Shadow endpoint that needs the scan's token is reported as reachable with credentials")
    void shadowNeedsCredentials() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/api/beta/items")
                ? (authed(r) ? json(200, "[{\"id\":1}]") : json(401, "{\"error\":\"unauthorized\"}"))
                : null);

        List<Finding> findings = new ImproperInventoryManagementTestCase().execute(endpoint("/api/v2/items", "GET"), client);

        Finding f = only(findings, "Shadow/Non-Production");
        assertTrue(f.getTitle().contains(PHRASE), f.getTitle());
        assertFalse(f.getDescription().contains("publicly accessible"), f.getDescription());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertNoCredentials(requestsTo("/api/beta/items").get(0));
    }

    @Test
    @DisplayName("Documentation probe carries no credentials; public documentation is LOW")
    void docsPublic() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/openapi.json") ? json(200, "{\"openapi\":\"3.0.0\"}") : null);

        List<Finding> findings = new ImproperInventoryManagementTestCase().execute(endpoint("/", "GET"), client);

        Finding f = only(findings, "API Documentation");
        assertEquals("API Documentation Publicly Exposed", f.getTitle());
        assertEquals(Severity.LOW, f.getSeverity());
        requestsTo("/openapi.json").forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("Documentation that needs the scan's token is reported as reachable with credentials")
    void docsNeedCredentials() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/openapi.json")
                ? (authed(r) ? json(200, "{\"openapi\":\"3.0.0\"}") : json(401, "{\"error\":\"unauthorized\"}"))
                : null);

        List<Finding> findings = new ImproperInventoryManagementTestCase().execute(endpoint("/", "GET"), client);

        Finding f = only(findings, "API Documentation");
        assertTrue(f.getTitle().contains(PHRASE), f.getTitle());
        assertFalse(f.getDescription().contains("publicly accessible"), f.getDescription());
        assertEquals(Severity.INFO, f.getSeverity());
        assertNoCredentials(requestsTo("/openapi.json").get(0));
    }

    // ── GraphQL IDE ────────────────────────────────────────────────────────

    private static MockResponse ide() {
        return new MockResponse().setResponseCode(200).setHeader("Content-Type", "text/html")
                .setBody("<html><div id=\"graphiql\">GraphiQL</div></html>");
    }

    @Test
    @DisplayName("GraphiQL probe carries no credentials; a public IDE is MEDIUM")
    void graphiqlPublic() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/graphiql") ? ide() : null);

        List<Finding> findings = new GraphQLSecurityTestCase().testGraphiQLExposure(endpoint("/graphql", "POST"), client);

        Finding f = only(findings, "GraphQL IDE");
        assertEquals("GraphQL IDE Exposed in Production", f.getTitle());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        requestsTo("/graphiql").forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("GraphiQL that needs the scan's token is reported as reachable with credentials")
    void graphiqlNeedsCredentials() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/graphiql")
                ? (authed(r) ? ide() : json(401, "{\"error\":\"unauthorized\"}"))
                : null);

        List<Finding> findings = new GraphQLSecurityTestCase().testGraphiQLExposure(endpoint("/graphql", "POST"), client);

        Finding f = only(findings, "GraphQL IDE");
        assertTrue(f.getTitle().contains(PHRASE), f.getTitle());
        assertFalse(f.getDescription().contains("publicly accessible"), f.getDescription());
        assertEquals(Severity.LOW, f.getSeverity());
        assertNoCredentials(requestsTo("/graphiql").get(0));
    }

    // ── Broken authentication: anonymous attacker checks ───────────────────

    @Test
    @DisplayName("Brute-force lockout check sends every login attempt without credentials")
    void bruteForceAnonymous() throws Exception {
        HttpClient client = start((r, path) -> path.equals("/api/login") ? json(401, "{\"error\":\"invalid\"}") : null);

        List<Finding> findings = new BrokenAuthenticationTestCase()
                .testBruteForceLockout(endpoint("/api/login", "POST"), client);

        assertEquals(1, findings.size(), titles(findings));
        assertFalse(requestsTo("/api/login").isEmpty());
        requestsTo("/api/login").forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("User enumeration check sends its login attempts without credentials")
    void userEnumerationAnonymous() throws Exception {
        HttpClient client = start((r, path) -> {
            if (!path.equals("/api/login")) return null;
            return r.getBody().clone().readUtf8().contains("nonexistent_")
                    ? json(404, "{\"error\":\"user not found\"}")
                    : json(401, "{\"error\":\"wrong password\"}");
        });

        List<Finding> findings = new BrokenAuthenticationTestCase()
                .testUserEnumeration(endpoint("/api/login", "POST"), client);

        Finding f = only(findings, "User Enumeration");
        assertEquals("User Enumeration via Differential Login Response", f.getTitle());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        requestsTo("/api/login").forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("User enumeration seen only with the scan's token is reported as reachable with credentials")
    void userEnumerationNeedsCredentials() throws Exception {
        HttpClient client = start((r, path) -> {
            if (!path.equals("/api/login")) return null;
            if (!authed(r)) return json(401, "{\"error\":\"api key required\"}");
            return r.getBody().clone().readUtf8().contains("nonexistent_")
                    ? json(404, "{\"error\":\"user not found\"}")
                    : json(401, "{\"error\":\"wrong password\"}");
        });

        List<Finding> findings = new BrokenAuthenticationTestCase()
                .testUserEnumeration(endpoint("/api/login", "POST"), client);

        Finding f = only(findings, "User Enumeration");
        assertTrue(f.getTitle().contains(PHRASE), f.getTitle());
        assertEquals(Severity.LOW, f.getSeverity());
        assertNoCredentials(requestsTo("/api/login").get(0));
    }

    // ── NoSQL authentication bypass on an auth-like endpoint ───────────────

    private static final String LOGIN_BODY = "{\"username\":\"alice\",\"password\":\"secret\"}";

    @Test
    @DisplayName("NoSQL auth bypass on a login endpoint is probed without credentials; an anonymous bypass is CRITICAL")
    void noSqlBypassAnonymous() throws Exception {
        HttpClient client = start((r, path) -> {
            if (!path.equals("/api/login")) return null;
            return r.getBody().clone().readUtf8().contains("$ne")
                    ? json(200, "{\"token\":\"abc\"}")
                    : json(401, "{\"error\":\"invalid credentials\"}");
        });

        List<Finding> findings = new SqlNoSqlInjectionTestCase()
                .execute(endpoint("/api/login", "POST", LOGIN_BODY, false), client);

        Finding f = only(findings, "Authentication Bypass");
        assertEquals("NoSQL Injection — Authentication Bypass", f.getTitle());
        assertEquals(Severity.CRITICAL, f.getSeverity());
        List<RecordedRequest> operatorRequests = received.stream()
                .filter(r -> "/api/login".equals(r.getPath()) && r.getBody().clone().readUtf8().contains("$ne"))
                .toList();
        assertFalse(operatorRequests.isEmpty());
        operatorRequests.forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    @Test
    @DisplayName("NoSQL bypass seen only with the scan's token is reported as reachable with credentials, not CRITICAL")
    void noSqlBypassNeedsCredentials() throws Exception {
        HttpClient client = start((r, path) -> {
            if (!path.equals("/api/login")) return null;
            return authed(r) && r.getBody().clone().readUtf8().contains("$ne")
                    ? json(200, "{\"token\":\"abc\"}")
                    : json(401, "{\"error\":\"invalid credentials\"}");
        });

        List<Finding> findings = new SqlNoSqlInjectionTestCase()
                .execute(endpoint("/api/login", "POST", LOGIN_BODY, false), client);

        assertFalse(findings.stream().anyMatch(f -> f.getSeverity() == Severity.CRITICAL), titles(findings));
        Finding f = only(findings, "Authentication Bypass");
        assertTrue(f.getTitle().contains(PHRASE), f.getTitle());
        assertEquals(Severity.HIGH, f.getSeverity());
    }

    // ── BOLA cross-user: secondary identity only ───────────────────────────

    @Test
    @DisplayName("BOLA cross-user request carries the secondary token and none of the primary credentials")
    void bolaSecondaryOnly() throws Exception {
        HttpClient client = startWithSecondary();

        List<Finding> findings = new BrokenObjectLevelAuthorizationTestCase()
                .execute(endpoint("/api/users/5", "GET", null, true), client);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")), titles(findings));
        List<RecordedRequest> secondary = received.stream()
                .filter(r -> "Bearer secondary-token".equals(r.getHeader("Authorization"))).toList();
        assertFalse(secondary.isEmpty(), "a secondary-identity request must have been sent");
        for (RecordedRequest r : secondary) {
            assertNull(r.getHeader("X-API-Key"), "primary API key rode along on the secondary request");
            assertNull(r.getHeader("X-Session-Token"), "primary custom credential rode along on the secondary request");
            assertNull(r.getHeader("Cookie"), "primary cookie rode along on the secondary request");
        }
    }

    private HttpClient startWithSecondary() throws Exception {
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
                return path.startsWith("/api/users/") ? json(200, "{\"id\":5,\"name\":\"bob\"}") : notFound();
            }
        });
        server.start();
        ScanConfig config = credentialedConfig(server.url("/").toString());
        config.setSecondaryBearerToken("secondary-token");
        HttpClient client = new HttpClient(config);
        client.getWithStatus(server.url("/session-cookie").toString(), Map.of());
        received.clear();
        return client;
    }

    // ── mTLS comparison ────────────────────────────────────────────────────

    @Test
    @DisplayName("mTLS comparison requests carry the client certificate but no token, API key or cookie")
    void mtlsNoTokenCredentials(@TempDir Path dir) throws Exception {
        Path p12 = dir.resolve("client.p12");
        generateKeystore(p12, "changeit");

        server = new MockWebServer();
        server.useHttps(serverSslContext(p12, "changeit").getSocketFactory(), false);
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                return json(200, "{\"ok\":true}")
                        .addHeader("Set-Cookie", "sid=primary-cookie; Path=/");
            }
        });
        server.start();

        ScanConfig config = credentialedConfig(server.url("/").toString());
        config.setClientCertPath(p12.toString());
        config.setClientCertPassword("changeit");
        config.setInvalidClientCertPath(p12.toString());
        config.setInvalidClientCertPassword("changeit");
        HttpClient client = new HttpClient(config);

        List<Finding> findings = new MutualTlsValidationTestCase().execute(endpoint("/api/secure", "GET"), client);

        assertEquals(1, findings.size(), titles(findings));
        assertEquals(2, received.size());
        received.forEach(UnauthenticatedChecksWireTest::assertNoCredentials);
    }

    private static void generateKeystore(Path p12, String password) throws Exception {
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        List<String> cmd = new ArrayList<>(List.of(keytool, "-genkeypair", "-alias", "test",
                "-keyalg", "RSA", "-keysize", "2048", "-storetype", "PKCS12",
                "-keystore", p12.toString(), "-storepass", password, "-keypass", password,
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2"));
        Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool timed out");
        assertEquals(0, process.exitValue(), "keytool failed");
    }

    private static SSLContext serverSslContext(Path p12, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(p12.toFile())) {
            keyStore.load(in, password.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);
        return context;
    }
}
