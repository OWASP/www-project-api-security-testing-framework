package org.owasp.astf.core.http;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.astf.core.config.ScanConfig;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wire-level checks that requests meant to carry no credentials, or only the secondary identity,
 * really leave the primary bearer token, API key, credential-like custom headers and cookies off.
 */
@DisplayName("HttpClient credential isolation")
class HttpClientCredentialIsolationTest {

    private MockWebServer server;
    private final List<RecordedRequest> received = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws IOException {
        if (server != null) {
            server.shutdown();
        }
    }

    private void startServer() throws IOException {
        server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                if (request.getPath() != null && request.getPath().startsWith("/login")) {
                    return new MockResponse().setResponseCode(200)
                            .addHeader("Set-Cookie", "sid=primary-cookie; Path=/");
                }
                return new MockResponse().setResponseCode(200).setBody("{}");
            }
        });
        server.start();
    }

    /** Client with every kind of primary credential configured and a session cookie captured. */
    private HttpClient credentialedClient(String targetUrl) throws IOException {
        ScanConfig config = new ScanConfig();
        config.setTargetUrl(targetUrl);
        config.setBearerToken("primary-token");
        config.setApiKey("primary-key");
        config.setApiKeyHeader("X-API-Key");
        config.addHeader("X-API-Key", "primary-key");
        config.addHeader("X-Session-Token", "custom-secret");
        config.addHeader("X-Custom-Static-Header", "keep-me");
        config.addHeader("X-User-Id", "42");
        config.addHeader("X-Hasura-Role", "admin");
        config.addHeader("X-Forwarded-User", "alice");
        config.addHeader("X-Remote-User", "alice");
        config.addHeader("X-Account-Id", "acct-7");
        config.addHeader("Accept", "application/vnd.test+json");
        config.addHeader("User-Agent", "astf-test-agent");
        config.addHeader("Accept-Language", "de-DE");
        config.setSecondaryBearerToken("secondary-token");
        return new HttpClient(config);
    }

    private void captureSessionCookie(HttpClient client) throws Exception {
        client.getWithStatus(server.url("/login").toString(), java.util.Map.of());
        received.clear();
    }

    private static void assertNoPrimaryCredentials(RecordedRequest r) {
        assertNull(r.getHeader("Authorization"), "Authorization must not be sent: " + r.getRequestLine());
        assertNull(r.getHeader("X-API-Key"), "API key must not be sent: " + r.getRequestLine());
        assertNull(r.getHeader("X-Session-Token"), "credential-like custom header must not be sent: " + r.getRequestLine());
        assertNull(r.getHeader("Cookie"), "cookies must not be sent: " + r.getRequestLine());
        assertNoIdentityHeaders(r);
    }

    /** Custom headers that name or select a user (or anything else not on the protocol allowlist). */
    private static final List<String> IDENTITY_HEADERS = List.of(
            "X-User-Id", "X-Hasura-Role", "X-Forwarded-User", "X-Remote-User", "X-Account-Id",
            "X-Custom-Static-Header");

    private static void assertNoIdentityHeaders(RecordedRequest r) {
        for (String name : IDENTITY_HEADERS) {
            assertNull(r.getHeader(name), name + " is part of the primary identity and must not be sent: "
                    + r.getRequestLine());
        }
    }

    /** The protocol headers the user configured are still sent, with the user's values. */
    private static void assertProtocolHeadersKept(RecordedRequest r) {
        assertEquals("application/vnd.test+json", r.getHeader("Accept"), r.getRequestLine());
        assertEquals("astf-test-agent", r.getHeader("User-Agent"), r.getRequestLine());
        assertEquals("de-DE", r.getHeader("Accept-Language"), r.getRequestLine());
    }

    @Test
    @DisplayName("Every NoAuth method sends no token, API key, credential header or cookie")
    void noAuthMethodsCarryNoCredentials() throws Exception {
        startServer();
        HttpClient client = credentialedClient(server.url("/").toString());
        captureSessionCookie(client);
        String url = server.url("/api/secure").toString();

        client.getWithStatusNoAuth(url);
        client.postWithStatusNoAuth(url, "application/json", "{}");
        client.putWithStatusNoAuth(url, "application/json", "{}");
        client.patchWithStatusNoAuth(url, "application/json", "{}");
        client.deleteWithStatusNoAuth(url);
        client.getNoAuth(url);
        client.sendWithStatusNoAuth("PATCH", url, "application/json", "{}");

        assertEquals(7, received.size());
        for (RecordedRequest r : received) {
            assertNoPrimaryCredentials(r);
            assertProtocolHeadersKept(r);
        }
        assertEquals("PATCH", received.get(3).getMethod());
    }

    @Test
    @DisplayName("Secondary-identity requests carry the secondary token and nothing of the primary identity")
    void secondaryRequestsCarryOnlySecondaryToken() throws Exception {
        startServer();
        HttpClient client = credentialedClient(server.url("/").toString());
        captureSessionCookie(client);
        String url = server.url("/api/users/5").toString();

        assertTrue(client.hasSecondaryIdentity());
        for (String method : List.of("GET", "POST", "PUT", "PATCH", "DELETE")) {
            client.sendWithStatusAsSecondary(method, url, "application/json", "{}");
        }

        assertEquals(5, received.size());
        for (RecordedRequest r : received) {
            assertEquals("Bearer secondary-token", r.getHeader("Authorization"), r.getRequestLine());
            assertNull(r.getHeader("X-API-Key"), "primary API key must not ride along: " + r.getRequestLine());
            assertNull(r.getHeader("X-Session-Token"), "primary custom credential must not ride along");
            assertNull(r.getHeader("Cookie"), "primary cookies must not ride along");
            assertNoIdentityHeaders(r);
            assertProtocolHeadersKept(r);
        }
    }

    @Test
    @DisplayName("Normal requests still carry every configured custom header")
    void normalRequestsKeepIdentityHeaders() throws Exception {
        startServer();
        HttpClient client = credentialedClient(server.url("/").toString());
        client.getWithStatus(server.url("/api/me").toString(), java.util.Map.of());

        RecordedRequest r = received.get(0);
        assertEquals("Bearer primary-token", r.getHeader("Authorization"));
        assertEquals("42", r.getHeader("X-User-Id"));
        assertEquals("admin", r.getHeader("X-Hasura-Role"));
        assertEquals("keep-me", r.getHeader("X-Custom-Static-Header"));
        assertProtocolHeadersKept(r);
    }

    @Test
    @DisplayName("No secondary identity configured means hasSecondaryIdentity is false")
    void noSecondaryIdentity() throws Exception {
        startServer();
        ScanConfig config = new ScanConfig();
        config.setTargetUrl(server.url("/").toString());
        HttpClient client = new HttpClient(config);
        assertFalse(client.hasSecondaryIdentity());
        assertFalse(client.hasConfiguredCredentials());
    }

    @Test
    @DisplayName("hasConfiguredCredentials reports configured token, API key, basic auth and identity headers only")
    void hasConfiguredCredentials() throws Exception {
        startServer();
        String target = server.url("/").toString();

        ScanConfig token = new ScanConfig();
        token.setTargetUrl(target);
        token.setBearerToken("t");
        assertTrue(new HttpClient(token).hasConfiguredCredentials());

        ScanConfig apiKey = new ScanConfig();
        apiKey.setTargetUrl(target);
        apiKey.setApiKey("k");
        assertTrue(new HttpClient(apiKey).hasConfiguredCredentials());

        ScanConfig basic = new ScanConfig();
        basic.setTargetUrl(target);
        basic.setBasicAuthUsername("u");
        basic.setBasicAuthPassword("p");
        assertTrue(new HttpClient(basic).hasConfiguredCredentials());

        ScanConfig custom = new ScanConfig();
        custom.setTargetUrl(target);
        custom.addHeader("X-Session-Token", "s");
        assertTrue(new HttpClient(custom).hasConfiguredCredentials());

        ScanConfig identity = new ScanConfig();
        identity.setTargetUrl(target);
        identity.addHeader("X-User-Id", "42");
        assertTrue(new HttpClient(identity).hasConfiguredCredentials(),
                "an identity header such as X-User-Id is part of the configured identity");

        ScanConfig none = new ScanConfig();
        none.setTargetUrl(target);
        none.addHeader("Accept", "application/json");
        none.addHeader("User-Agent", "astf-test-agent");
        HttpClient plain = new HttpClient(none);
        assertFalse(plain.hasConfiguredCredentials());
        captureSessionCookie(plain);
        assertFalse(plain.hasConfiguredCredentials(),
                "a cookie the target set during a scan with no credentials is not a configured credential");
    }

    @Test
    @DisplayName("Client-certificate requests carry no bearer token, API key, credential header or cookie")
    void clientCertRequestsCarryNoTokenCredentials(@TempDir Path dir) throws Exception {
        Path p12 = dir.resolve("test.p12");
        generateKeystore(p12, "changeit");

        server = new MockWebServer();
        server.useHttps(serverSslContext(p12, "changeit").getSocketFactory(), false);
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                if (request.getPath() != null && request.getPath().startsWith("/login")) {
                    return new MockResponse().setResponseCode(200)
                            .addHeader("Set-Cookie", "sid=primary-cookie; Path=/");
                }
                return new MockResponse().setResponseCode(200).setBody("{}");
            }
        });
        server.start();

        HttpClient client = credentialedClient(server.url("/").toString());
        // Capture the cookie over the same TLS client the cert requests use, so the jar would
        // have something to attach if the cert client still shared it.
        client.getWithClientCert(server.url("/login").toString(), java.util.Map.of(),
                p12.toString(), "changeit");
        received.clear();

        HttpResponse response = client.getWithClientCert(server.url("/api/secure").toString(),
                java.util.Map.of(), p12.toString(), "changeit");

        assertEquals(200, response.getStatusCode());
        assertEquals(1, received.size());
        assertNoPrimaryCredentials(received.get(0));
    }

    static void generateKeystore(Path p12, String password) throws Exception {
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

    static SSLContext serverSslContext(Path p12, String password) throws Exception {
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
