package org.owasp.astf.testcases;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
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
 * Runs {@link MutualTlsValidationTestCase} with a real {@link HttpClient} against a TLS
 * MockWebServer that asks for a client certificate, so each recorded request shows which
 * certificate was presented and which credentials were sent with it.
 */
@DisplayName("Mutual TLS validation on the wire")
class MutualTlsValidationWireTest {

    private static final String PASSWORD = "changeit";
    private static final String VALID_CN = "valid-client";
    private static final String UNTRUSTED_CN = "untrusted-client";

    @TempDir
    static Path dir;
    private static Path serverP12;
    private static Path validP12;
    private static Path untrustedP12;

    private MockWebServer server;
    private final List<RecordedRequest> received = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void keystores() throws Exception {
        serverP12 = dir.resolve("server.p12");
        validP12 = dir.resolve("valid.p12");
        untrustedP12 = dir.resolve("untrusted.p12");
        generateKeystore(serverP12, "localhost");
        generateKeystore(validP12, VALID_CN);
        generateKeystore(untrustedP12, UNTRUSTED_CN);
    }

    @AfterEach
    void tearDown() throws IOException {
        if (server != null) {
            server.shutdown();
        }
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStorePassword");
        System.clearProperty("javax.net.ssl.trustStoreType");
    }

    /**
     * Makes the JVM's default trust store contain the test server's certificate. The credentialed
     * comparison validates the server certificate (it sends a token), so tests that exercise it
     * need a server the JVM trusts, as a real deployment would have.
     */
    private static void trustTestServer() throws Exception {
        KeyStore serverStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(serverP12.toFile())) {
            serverStore.load(in, PASSWORD.toCharArray());
        }
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("test-server", serverStore.getCertificate("test"));
        Path trustFile = dir.resolve("truststore-" + System.nanoTime() + ".p12");
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(trustFile.toFile())) {
            trust.store(out, PASSWORD.toCharArray());
        }
        System.setProperty("javax.net.ssl.trustStore", trustFile.toString());
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
    }

    private void startServer(Function<RecordedRequest, Integer> status) throws Exception {
        server = new MockWebServer();
        server.useHttps(serverSslContext().getSocketFactory(), false);
        server.requestClientAuth();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                return new MockResponse().setResponseCode(status.apply(request)).setBody("{\"data\":\"ok\"}");
            }
        });
        server.start();
    }

    private HttpClient client(boolean withCredentials) {
        ScanConfig config = new ScanConfig();
        config.setTargetUrl(server.url("/").toString());
        if (withCredentials) {
            config.setBearerToken("primary-token");
            config.setApiKey("primary-key");
            config.setApiKeyHeader("X-API-Key");
            config.addHeader("X-API-Key", "primary-key");
        }
        config.setClientCertPath(validP12.toString());
        config.setClientCertPassword(PASSWORD);
        config.setInvalidClientCertPath(untrustedP12.toString());
        config.setInvalidClientCertPassword(PASSWORD);
        return new HttpClient(config);
    }

    private List<Finding> run(HttpClient client) throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/secure", "GET");
        endpoint.setBaseUrl("https://" + server.getHostName() + ":" + server.getPort());
        return new MutualTlsValidationTestCase().execute(endpoint, client);
    }

    private static boolean hasToken(RecordedRequest r) {
        return "Bearer primary-token".equals(r.getHeader("Authorization"));
    }

    private static String clientCn(RecordedRequest r) {
        if (r.getHandshake() == null || r.getHandshake().peerCertificates().isEmpty()) {
            return null;
        }
        Certificate cert = r.getHandshake().peerCertificates().get(0);
        String dn = ((X509Certificate) cert).getSubjectX500Principal().getName();
        return dn.replaceFirst("^CN=", "").replaceFirst(",.*$", "");
    }

    private static void assertCertificateOnly(RecordedRequest r) {
        assertNull(r.getHeader("Authorization"), "certificate-only request must not carry a token");
        assertNull(r.getHeader("X-API-Key"), "certificate-only request must not carry the API key");
        assertNull(r.getHeader("Cookie"), "certificate-only request must not carry cookies");
    }

    @Test
    @DisplayName("Certificate alone accepted: only the certificate-only pair is sent, unchanged")
    void certificateOnlyAccepted() throws Exception {
        startServer(r -> 200);

        List<Finding> findings = run(client(true));

        assertEquals(2, received.size(), "no credentialed pair when the certificate alone is accepted");
        for (RecordedRequest r : received) {
            assertCertificateOnly(r);
        }
        assertEquals(VALID_CN, clientCn(received.get(0)));
        assertEquals(UNTRUSTED_CN, clientCn(received.get(1)));

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertEquals("Arbitrary Client Certificate Accepted (mTLS)", f.getTitle());
        assertEquals(Severity.CRITICAL, f.getSeverity());
        assertFalse(f.getEvidence().contains("configured credentials"), f.getEvidence());
    }

    @Test
    @DisplayName("Certificate alone rejected but certificate plus token accepted: the comparison still runs")
    void certificateOnlyRejectedButCertificateWithTokenAccepted() throws Exception {
        // Server needs the token and does not check the client certificate at all.
        trustTestServer();
        startServer(r -> hasToken(r) ? 200 : 401);

        List<Finding> findings = run(client(true));

        assertEquals(3, received.size(),
                "valid certificate alone, then both certificates with the configured credentials");
        assertCertificateOnly(received.get(0));
        assertEquals(VALID_CN, clientCn(received.get(0)));
        for (RecordedRequest r : received.subList(1, 3)) {
            assertTrue(hasToken(r), "credentialed pair must carry the configured token");
            assertEquals("primary-key", r.getHeader("X-API-Key"));
        }
        assertEquals(VALID_CN, clientCn(received.get(1)));
        assertEquals(UNTRUSTED_CN, clientCn(received.get(2)));

        assertEquals(1, findings.size());
        Finding f = findings.get(0);
        assertTrue(f.getTitle().startsWith("Arbitrary Client Certificate Accepted (mTLS"), f.getTitle());
        assertTrue(f.getTitle().contains("with the configured credentials"), f.getTitle());
        assertTrue(f.getEvidence().contains("configured credentials"), f.getEvidence());
        assertTrue(f.getEvidence().contains("HTTP 401"), f.getEvidence());
        assertEquals(Severity.HIGH, f.getSeverity());
    }

    @Test
    @DisplayName("Certificate plus token: no finding when the server rejects the untrusted certificate")
    void certificateWithTokenUntrustedRejected() throws Exception {
        trustTestServer();
        startServer(r -> !hasToken(r) ? 401 : UNTRUSTED_CN.equals(clientCn(r)) ? 403 : 200);

        List<Finding> findings = run(client(true));

        assertEquals(3, received.size());
        assertCertificateOnly(received.get(0));
        assertTrue(hasToken(received.get(1)));
        assertTrue(hasToken(received.get(2)));
        assertEquals(UNTRUSTED_CN, clientCn(received.get(2)));
        assertTrue(findings.isEmpty(), "untrusted certificate was rejected; nothing to report");
    }

    @Test
    @DisplayName("Server certificate the JVM does not trust: no token is sent, and the comparison not being made is reported")
    void untrustedServerCertificateNeverReceivesCredentials() throws Exception {
        startServer(r -> hasToken(r) ? 200 : 401);   // the JVM trust store does not contain this server

        List<Finding> findings = run(client(true));

        assertTrue(received.stream().noneMatch(MutualTlsValidationWireTest::hasToken),
                "no request carrying the token may reach a server whose certificate does not validate");
        assertTrue(received.stream().noneMatch(r -> r.getHeader("X-API-Key") != null));
        assertEquals(1, findings.size(), findings.toString());
        assertEquals(Severity.INFO, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getTitle().contains("Not Made"), findings.get(0).getTitle());
    }

    @Test
    @DisplayName("No credentials configured: certificate alone rejected means no comparison")
    void noCredentialsConfigured() throws Exception {
        startServer(r -> 401);

        List<Finding> findings = run(client(false));

        assertEquals(1, received.size());
        assertCertificateOnly(received.get(0));
        assertTrue(findings.isEmpty());
    }

    static void generateKeystore(Path p12, String cn) throws Exception {
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        List<String> cmd = new ArrayList<>(List.of(keytool, "-genkeypair", "-alias", "test",
                "-keyalg", "RSA", "-keysize", "2048", "-storetype", "PKCS12",
                "-keystore", p12.toString(), "-storepass", PASSWORD, "-keypass", PASSWORD,
                "-dname", "CN=" + cn, "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2"));
        Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool timed out");
        assertEquals(0, process.exitValue(), "keytool failed");
    }

    /** Server context that asks for any client certificate and records it, deciding nothing at TLS level. */
    private static SSLContext serverSslContext() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(serverP12.toFile())) {
            keyStore.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, PASSWORD.toCharArray());
        X509TrustManager acceptAnyClient = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) { }
            public void checkServerTrusted(X509Certificate[] chain, String authType) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), new TrustManager[]{acceptAnyClient}, new SecureRandom());
        return context;
    }
}
