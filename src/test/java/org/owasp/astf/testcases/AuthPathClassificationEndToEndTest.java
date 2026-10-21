package org.owasp.astf.testcases;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end checks (real HttpClient, real MockWebServer) that path classification by whole
 * segment keeps the generic checks running on paths that merely contain an auth keyword as a
 * substring, and still sends the auth/2FA-specific probes to real auth and 2FA paths.
 */
@DisplayName("BrokenAuthentication path classification (end to end)")
class AuthPathClassificationEndToEndTest {

    private MockWebServer server;
    private final List<RecordedRequest> received = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws IOException {
        if (server != null) {
            server.shutdown();
        }
    }

    /** Server that answers 200 with data to everything, with or without credentials. */
    private HttpClient startOpenServer() throws IOException {
        server = new MockWebServer();
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                received.add(request);
                return new MockResponse().setResponseCode(200)
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"items\":[{\"id\":1,\"name\":\"x\"}]}");
            }
        });
        server.start();
        ScanConfig config = new ScanConfig();
        config.setTargetUrl(server.url("/").toString());
        config.setBearerToken("real-token");
        return new HttpClient(config);
    }

    private List<Finding> run(String path, String method, boolean requiresAuth) throws IOException {
        HttpClient client = startOpenServer();
        EndpointInfo endpoint = new EndpointInfo(path, method, "application/json", null, requiresAuth);
        endpoint.setBaseUrl(server.url("/").toString());
        return new BrokenAuthenticationTestCase().execute(endpoint, client);
    }

    @ParameterizedTest(name = "missing-auth check runs on {0}")
    @ValueSource(strings = {"/api/tokens", "/api/authors", "/api/discount-codes", "/api/otpauth-free-paths"})
    @DisplayName("Paths that only contain an auth/2FA keyword as a substring get the generic missing-auth check")
    void missingAuthCheckRunsOnSubstringOnlyPaths(String path) throws Exception {
        List<Finding> findings = run(path, "GET", true);

        assertTrue(findings.stream().anyMatch(f -> "Missing Authentication Controls".equals(f.getTitle())),
                "GET " + path + " answers 200 with data and no credentials, so the missing-auth "
                        + "check must run and report it; findings were " + titles(findings));
        assertTrue(received.stream().anyMatch(r -> r.getPath().startsWith(path)
                        && r.getHeader("Authorization") == null),
                "An unauthenticated request must actually have been sent to " + path);
    }

    @Test
    @DisplayName("/api/tokens is no longer sent login brute-force probes")
    void tokensPathIsNotTreatedAsLogin() throws Exception {
        run("/api/tokens", "POST", true);

        assertFalse(received.stream().anyMatch(r -> r.getBody().clone().readUtf8().contains("\"password\"")),
                "/api/tokens is not a login path, so no credential guessing should be sent to it");
    }

    @Test
    @DisplayName("A real login path still gets the auth-specific probes")
    void realLoginPathStillGetsAuthProbes() throws Exception {
        run("/api/v1/auth/login", "POST", false);

        assertTrue(received.stream().anyMatch(r -> r.getBody().clone().readUtf8().toLowerCase().contains("password")),
                "/api/v1/auth/login must still receive the credential probes");
    }

    @Test
    @DisplayName("A real 2FA path still gets the OTP bypass probes")
    void real2faPathStillGetsOtpProbes() throws Exception {
        List<Finding> findings = run("/api/2fa/verify", "POST", false);

        assertTrue(received.stream().anyMatch(r -> r.getBody().clone().readUtf8().contains("\"code\":\"000000\"")),
                "/api/2fa/verify must still receive the weak-OTP probes");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().startsWith("2FA/MFA Bypass")),
                "the open 2FA endpoint accepts a weak code and must be reported; findings were " + titles(findings));
    }

    private static List<String> titles(List<Finding> findings) {
        List<String> t = new ArrayList<>();
        findings.forEach(f -> t.add(f.getTitle()));
        return t;
    }
}
