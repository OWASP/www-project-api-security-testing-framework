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
            assertEquals("keep-me", r.getHeader("X-Custom-Static-Header"),
                    "non-credential custom headers are still sent");
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
        }
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
    @DisplayName("hasConfiguredCredentials reports token, API key, basic auth and captured cookies")
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

        ScanConfig none = new ScanConfig();
        none.setTargetUrl(target);
        none.addHeader("X-Custom-Static-Header", "keep-me");
        HttpClient plain = new HttpClient(none);
        assertFalse(plain.hasConfiguredCredentials());
        captureSessionCookie(plain);
        assertTrue(plain.hasConfiguredCredentials(), "a captured session cookie is a credential");
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
