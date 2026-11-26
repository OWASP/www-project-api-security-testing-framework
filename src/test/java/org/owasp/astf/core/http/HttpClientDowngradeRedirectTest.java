package org.owasp.astf.core.http;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.astf.core.config.ScanConfig;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A redirect from https to http must not carry credentials, even to a host the user listed in
 * scopeHosts without a port (which matches every port of that host). The redirected request is
 * still made.
 */
@DisplayName("HttpClient: https to http redirects never carry credentials")
class HttpClientDowngradeRedirectTest {

    private static final String PASSWORD = "changeit";

    @TempDir
    Path dir;
    private MockWebServer tls;
    private MockWebServer plain;

    @AfterEach
    void tearDown() throws Exception {
        if (tls != null) {
            tls.shutdown();
        }
        if (plain != null) {
            plain.shutdown();
        }
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStorePassword");
        System.clearProperty("javax.net.ssl.trustStoreType");
    }

    private KeyStore generateServerKeystore() throws Exception {
        Path p12 = dir.resolve("server.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        List<String> cmd = new ArrayList<>(List.of(keytool, "-genkeypair", "-alias", "test", "-keyalg", "RSA",
                "-keysize", "2048", "-storetype", "PKCS12", "-keystore", p12.toString(), "-storepass", PASSWORD,
                "-keypass", PASSWORD, "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1",
                "-validity", "2"));
        Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS));
        assertEquals(0, process.exitValue());
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(p12.toFile())) {
            store.load(in, PASSWORD.toCharArray());
        }
        return store;
    }

    @Test
    @DisplayName("An https target redirecting to plain http on a host listed without a port gets no credentials, and the request is still made")
    void downgradeRedirectToListedHostCarriesNoCredentials() throws Exception {
        KeyStore server = generateServerKeystore();
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("server", server.getCertificate("test"));
        Path trustFile = dir.resolve("trust.p12");
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(trustFile.toFile())) {
            trust.store(out, PASSWORD.toCharArray());
        }
        System.setProperty("javax.net.ssl.trustStore", trustFile.toString());
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(server, PASSWORD.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        plain = new MockWebServer();
        plain.start();
        plain.enqueue(new MockResponse().setResponseCode(200).setBody("{\"ok\":true}"));

        tls = new MockWebServer();
        tls.useHttps(context.getSocketFactory(), false);
        tls.start();
        HttpUrl downgradeTarget = plain.url("/landing").newBuilder().host("localhost").build();
        tls.enqueue(new MockResponse().setResponseCode(302).setHeader("Location", downgradeTarget.toString()));

        ScanConfig config = new ScanConfig();
        config.setTargetUrl(tls.url("/").newBuilder().host("localhost").build().toString());
        config.setBearerToken("primary-secret");
        config.setApiKey("key-secret");
        config.setApiKeyHeader("X-Api-Token");
        config.addHeader("X-Api-Token", "key-secret");
        config.addHeader("X-Session-Id", "custom-secret");
        config.setScopeHosts(List.of("localhost"));   // host without a port: every port of localhost
        HttpClient client = new HttpClient(config);

        HttpResponse response = client.getWithStatus(config.getTargetUrl() + "start", Map.of());

        assertEquals(200, response.getStatusCode(), "the redirected request must still be made");
        RecordedRequest first = tls.takeRequest(5, TimeUnit.SECONDS);
        assertEquals("Bearer primary-secret", first.getHeader("Authorization"), "the https target gets credentials");
        RecordedRequest second = plain.takeRequest(5, TimeUnit.SECONDS);
        assertFalse(second == null, "the plain http hop was requested");
        assertNull(second.getHeader("Authorization"), "no bearer token over plain http");
        assertNull(second.getHeader("X-Api-Token"), "no API key over plain http");
        assertNull(second.getHeader("X-Session-Id"), "no custom credential header over plain http");
        assertNull(second.getHeader("Cookie"));
    }

    @Test
    @DisplayName("The downgrade rule: only an https start with a non-https hop is a downgrade")
    void downgradeRule() {
        HttpUrl https = HttpUrl.parse("https://a.example/x");
        HttpUrl http = HttpUrl.parse("http://a.example/x");
        assertTrue(HttpClient.isSchemeDowngrade(https, http));
        assertFalse(HttpClient.isSchemeDowngrade(http, https), "an upgrade is not a downgrade");
        assertFalse(HttpClient.isSchemeDowngrade(http, http));
        assertFalse(HttpClient.isSchemeDowngrade(https, https));
    }
}
