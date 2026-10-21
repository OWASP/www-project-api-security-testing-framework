package org.owasp.astf.core.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.astf.core.config.ScanConfig;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Edge cases of keeping credentials on the target: a same-host http to https upgrade, a
 * Proxy-Authorization custom header, and a redirect chain that leaves the target and comes back.
 */
@DisplayName("HttpClient host pinning edge cases")
class HttpClientHostPinningEdgeCasesTest {

    private final java.util.List<MockWebServer> servers = new java.util.ArrayList<>();

    private MockWebServer start(MockWebServer server) throws IOException {
        server.start();
        servers.add(server);
        return server;
    }

    private MockWebServer target;
    private MockWebServer other;
    private ScanConfig config;

    @BeforeEach
    void setUp() throws Exception {
        target = start(new MockWebServer());
        other = start(new MockWebServer());
        config = new ScanConfig();
        config.setTargetUrl(target.url("/").toString());
        config.setBearerToken("primary-secret");
        config.setApiKey("key-secret");
        config.setApiKeyHeader("X-Api-Token");
        config.addHeader("X-Api-Token", "key-secret");
        config.addHeader("X-Session-Id", "custom-secret");
    }

    @AfterEach
    void tearDown() throws Exception {
        for (MockWebServer s : servers) {
            s.shutdown();
        }
    }

    // ------------------------------------------------------------------ (3) Proxy-Authorization

    @Test
    @DisplayName("A Proxy-Authorization custom header is not sent to an out-of-scope host")
    void customProxyAuthorizationStrippedOffTarget() throws Exception {
        config.addHeader("Proxy-Authorization", "Basic cHJveHk6c2VjcmV0");
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/landing")));
        other.enqueue(new MockResponse().setBody("other"));

        HttpResponse response = new HttpClient(config).getWithStatus(target.url("/start").toString(), Map.of());

        assertEquals(200, response.getStatusCode());
        RecordedRequest first = target.takeRequest(5, TimeUnit.SECONDS);
        assertEquals("Basic cHJveHk6c2VjcmV0", first.getHeader("Proxy-Authorization"),
                "the target itself still receives every configured header");
        RecordedRequest hop = other.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(hop, "the out-of-scope hop is still requested");
        assertNull(hop.getHeader("Proxy-Authorization"), "Proxy-Authorization leaked to " + hop.getRequestUrl());
        assertNull(hop.getHeader("Authorization"));
        assertNull(hop.getHeader("X-Session-Id"));
    }

    @Test
    @DisplayName("A direct out-of-scope request also drops a per-request Proxy-Authorization")
    void perRequestProxyAuthorizationStrippedOffTarget() throws Exception {
        other.enqueue(new MockResponse().setBody("x"));

        new HttpClient(config).getWithStatus(other.url("/spec.json").toString(),
                Map.of("Proxy-Authorization", "Basic cGVyOnJlcXVlc3Q="));

        RecordedRequest r = other.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(r);
        assertNull(r.getHeader("Proxy-Authorization"));
    }

    @Test
    @DisplayName("Through a plain-http proxy, Proxy-Authorization still reaches the proxy for an out-of-scope host")
    void proxyAuthorizationKeptForHttpProxy() throws Exception {
        MockWebServer proxy = start(new MockWebServer());
        config.setProxyHost(proxy.getHostName());
        config.setProxyPort(proxy.getPort());
        config.addHeader("Proxy-Authorization", "Basic cHJveHk6c2VjcmV0");
        proxy.enqueue(new MockResponse().setBody("via proxy"));

        HttpResponse response = new HttpClient(config).getWithStatus(other.url("/offsite").toString(), Map.of());

        assertEquals("via proxy", response.getBody());
        RecordedRequest r = proxy.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(r);
        assertEquals("Basic cHJveHk6c2VjcmV0", r.getHeader("Proxy-Authorization"),
                "a plain-http proxy consumes Proxy-Authorization from the request it forwards");
        assertNull(r.getHeader("Authorization"), "the origin credentials are still stripped");
        assertNull(r.getHeader("X-Session-Id"));
        assertEquals(0, other.getRequestCount(), "the request went through the proxy");
    }

    // ------------------------------------------------------------------ (4) target -> scope -> target

    @Test
    @DisplayName("Redirect chain target -> scopeHost -> target keeps Authorization on every hop")
    void authorizationRestoredOnReturnToTarget() throws Exception {
        config.setScopeHosts(List.of(other.getHostName() + ":" + other.getPort()));
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/sso")));
        other.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", target.url("/back")));
        target.enqueue(new MockResponse().setBody("home"));

        HttpResponse response = new HttpClient(config).getWithStatus(target.url("/start").toString(), Map.of());

        assertEquals("home", response.getBody());
        RecordedRequest first = target.takeRequest(5, TimeUnit.SECONDS);
        RecordedRequest middle = other.takeRequest(5, TimeUnit.SECONDS);
        RecordedRequest back = target.takeRequest(5, TimeUnit.SECONDS);
        assertEquals("/back", back.getPath());
        for (RecordedRequest r : List.of(first, middle, back)) {
            assertEquals("Bearer primary-secret", r.getHeader("Authorization"),
                    "Authorization missing on " + r.getRequestUrl());
            assertEquals("key-secret", r.getHeader("X-Api-Token"));
            assertEquals("custom-secret", r.getHeader("X-Session-Id"));
        }
    }

    @Test
    @DisplayName("A per-request Authorization is the one restored on the hop back to the target")
    void perRequestAuthorizationRestoredOnReturnToTarget() throws Exception {
        config.setScopeHosts(List.of(other.getHostName()));
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/sso")));
        other.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", target.url("/back")));
        target.enqueue(new MockResponse().setBody("home"));

        new HttpClient(config).getWithStatus(target.url("/start").toString(),
                Map.of("Authorization", "Bearer forged-probe"));

        target.takeRequest(5, TimeUnit.SECONDS);
        assertEquals("Bearer forged-probe", other.takeRequest(5, TimeUnit.SECONDS).getHeader("Authorization"));
        assertEquals("Bearer forged-probe", target.takeRequest(5, TimeUnit.SECONDS).getHeader("Authorization"));
    }

    @Test
    @DisplayName("A no-auth request gets no Authorization back on the hop back to the target")
    void noAuthStaysBareOnReturnToTarget() throws Exception {
        config.setScopeHosts(List.of(other.getHostName()));
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/sso")));
        other.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", target.url("/back")));
        target.enqueue(new MockResponse().setBody("home"));

        new HttpClient(config).getWithStatusNoAuth(target.url("/start").toString());

        for (RecordedRequest r : List.of(target.takeRequest(5, TimeUnit.SECONDS),
                other.takeRequest(5, TimeUnit.SECONDS), target.takeRequest(5, TimeUnit.SECONDS))) {
            assertNull(r.getHeader("Authorization"));
            assertNull(r.getHeader("X-Api-Token"));
        }
    }

    // ------------------------------------------------------------------ (1) http -> https upgrade

    /**
     * Sends connections for localhost:80 to {@code plain} and localhost:443 to {@code tls}, so a
     * redirect between the default ports can be followed without binding privileged ports.
     */
    private static SocketFactory defaultPortsTo(int plainPort, int tlsPort) {
        return new SocketFactory() {
            @Override
            public Socket createSocket() {
                return new Socket() {
                    @Override
                    public void connect(SocketAddress endpoint, int timeout) throws IOException {
                        InetSocketAddress a = (InetSocketAddress) endpoint;
                        int port = a.getPort() == 80 ? plainPort : a.getPort() == 443 ? tlsPort : a.getPort();
                        super.connect(new InetSocketAddress(a.getAddress(), port), timeout);
                    }
                };
            }

            @Override
            public Socket createSocket(String host, int port) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Socket createSocket(InetAddress host, int port) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private static X509TrustManager trustManagerFor(Path p12, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(p12.toFile())) {
            keyStore.load(in, password.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        return (X509TrustManager) tmf.getTrustManagers()[0];
    }

    @Test
    @DisplayName("http://host redirecting to https://host on the default ports keeps every credential")
    void sameHostSchemeUpgradeIsInScope(@TempDir Path dir) throws Exception {
        Path p12 = dir.resolve("upgrade.p12");
        HttpClientCredentialIsolationTest.generateKeystore(p12, "changeit");
        SSLContext serverContext = HttpClientCredentialIsolationTest.serverSslContext(p12, "changeit");
        MockWebServer tls = new MockWebServer();
        tls.useHttps(serverContext.getSocketFactory(), false);
        start(tls);

        ScanConfig upgrade = new ScanConfig();
        upgrade.setTargetUrl("http://localhost/");
        upgrade.setBearerToken("primary-secret");
        upgrade.setApiKey("key-secret");
        upgrade.setApiKeyHeader("X-Api-Token");
        upgrade.addHeader("X-Api-Token", "key-secret");
        upgrade.addHeader("X-Session-Id", "custom-secret");

        target.enqueue(new MockResponse().setResponseCode(301).addHeader("Location", "https://localhost/api/users"));
        tls.enqueue(new MockResponse().setBody("secure"));

        X509TrustManager trust = trustManagerFor(p12, "changeit");
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, new X509TrustManager[]{trust}, null);
        HttpClient client = new HttpClient(upgrade, b -> b
                .socketFactory(defaultPortsTo(target.getPort(), tls.getPort()))
                .sslSocketFactory(clientContext.getSocketFactory(), trust));

        HttpResponse response = client.getWithStatus("http://localhost/api/users", Map.of());

        assertEquals("secure", response.getBody());
        RecordedRequest first = target.takeRequest(5, TimeUnit.SECONDS);
        assertEquals("Bearer primary-secret", first.getHeader("Authorization"));
        RecordedRequest upgraded = tls.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(upgraded, "the https hop must be requested");
        assertEquals("/api/users", upgraded.getPath());
        assertEquals("Bearer primary-secret", upgraded.getHeader("Authorization"),
                "the upgraded hop on the target's own host keeps Authorization");
        assertEquals("key-secret", upgraded.getHeader("X-Api-Token"));
        assertEquals("custom-secret", upgraded.getHeader("X-Session-Id"));
    }

    @Test
    @DisplayName("Scope rule: only a same-host upgrade between the default ports is admitted")
    void schemeUpgradeScopeRule() {
        ScanConfig c = new ScanConfig();
        c.setTargetUrl("http://api.example.test/");
        HttpClient client = new HttpClient(c);
        assertTrue(client.isInCredentialScope(HttpUrl.get("https://api.example.test/x")));
        assertTrue(client.isInCredentialScope(HttpUrl.get("https://API.example.test:443/x")));
        assertFalse(client.isInCredentialScope(HttpUrl.get("https://api.example.test:8443/x")));
        assertFalse(client.isInCredentialScope(HttpUrl.get("http://api.example.test:8080/x")));
        assertFalse(client.isInCredentialScope(HttpUrl.get("https://other.example.test/x")));

        ScanConfig tlsTarget = new ScanConfig();
        tlsTarget.setTargetUrl("https://api.example.test/");
        assertFalse(new HttpClient(tlsTarget).isInCredentialScope(HttpUrl.get("http://api.example.test/x")),
                "a downgrade to cleartext is not a scheme upgrade and stays out of scope");

        ScanConfig nonDefault = new ScanConfig();
        nonDefault.setTargetUrl("http://api.example.test:8080/");
        assertFalse(new HttpClient(nonDefault).isInCredentialScope(HttpUrl.get("https://api.example.test/x")),
                "a target on a non-default port does not admit port 443");
    }
}
