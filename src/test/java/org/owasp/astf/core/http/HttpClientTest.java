package org.owasp.astf.core.http;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("HttpClient Tests")
class HttpClientTest {

    private MockWebServer server;
    private ScanConfig config;
    private HttpClient client;

    @BeforeEach
    void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
        config = new ScanConfig();
        config.setTargetUrl(server.url("/").toString());
        client = new HttpClient(config);
    }

    @AfterEach
    void tearDown() throws Exception {
        server.shutdown();
    }

    @Test
    @DisplayName("Cookie jar must be safe under concurrent saveFromResponse/loadForRequest")
    void testCookieJarConcurrentAccess() throws Exception {
        Field f = HttpClient.class.getDeclaredField("client");
        f.setAccessible(true);
        CookieJar jar = ((OkHttpClient) f.get(client)).cookieJar();

        int threads = 32;
        int iterations = 500;
        int hosts = 4;
        HttpUrl[] urls = new HttpUrl[hosts];
        for (int h = 0; h < hosts; h++) {
            urls[h] = HttpUrl.get("http://host" + h + ".test/");
        }

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int id = t;
            futures.add(pool.submit(() -> {
                start.await();
                for (int i = 0; i < iterations; i++) {
                    HttpUrl url = urls[(id + i) % hosts];
                    // Shared cookie name forces replace-in-place contention; unique name must never be lost.
                    jar.saveFromResponse(url, List.of(
                            new Cookie.Builder().name("shared").value("v" + id + "-" + i).domain(url.host()).build(),
                            new Cookie.Builder().name("t" + id + "-" + i).value("x").domain(url.host()).build()));
                    jar.loadForRequest(url);
                }
                return null;
            }));
        }
        start.countDown();
        for (Future<?> fu : futures) {
            fu.get(60, TimeUnit.SECONDS);
        }
        pool.shutdown();

        for (int h = 0; h < hosts; h++) {
            List<Cookie> loaded = jar.loadForRequest(urls[h]);
            long shared = loaded.stream().filter(c -> c.name().equals("shared")).count();
            assertEquals(1, shared, "exactly one 'shared' cookie expected for " + urls[h].host());
            // Each (thread, iteration) pair maps to exactly one host, so count the unique cookies expected here.
            int expected = 0;
            for (int t = 0; t < threads; t++) {
                for (int i = 0; i < iterations; i++) {
                    if ((t + i) % hosts == h) expected++;
                }
            }
            assertEquals(expected + 1, loaded.size(), "no cookie may be lost for " + urls[h].host());
        }
    }

    // -------------------------------------------------------------------------
    // GET
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should make GET request and return response body")
    void testGet() throws Exception {
        server.enqueue(new MockResponse().setBody("{\"status\":\"ok\"}").setResponseCode(200));

        String response = client.get(server.url("/api/test").toString(), Map.of());

        assertNotNull(response);
        assertTrue(response.contains("ok"));
        RecordedRequest recorded = server.takeRequest();
        assertEquals("GET", recorded.getMethod());
    }

    @Test
    @DisplayName("Should return HttpResponse with status 200 for getWithStatus")
    void testGetWithStatus200() throws Exception {
        server.enqueue(new MockResponse().setBody("{\"data\":\"value\"}").setResponseCode(200));

        HttpResponse response = client.getWithStatus(server.url("/api/data").toString(), Map.of());

        assertEquals(200, response.getStatusCode());
        assertTrue(response.isSuccess());
        assertFalse(response.isUnauthorized());
        assertTrue(response.getBody().contains("value"));
    }

    @Test
    @DisplayName("Should detect 401 Unauthorized response")
    void testGetWithStatus401() throws Exception {
        server.enqueue(new MockResponse().setBody("{\"error\":\"unauthorized\"}").setResponseCode(401));

        HttpResponse response = client.getWithStatus(server.url("/api/secure").toString(), Map.of());

        assertEquals(401, response.getStatusCode());
        assertTrue(response.isUnauthorized());
        assertFalse(response.isSuccess());
    }

    @Test
    @DisplayName("Should detect 403 Forbidden response")
    void testGetWithStatus403() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(403));

        HttpResponse response = client.getWithStatus(server.url("/api/admin").toString(), Map.of());

        assertTrue(response.isForbidden());
    }

    @Test
    @DisplayName("Should detect 429 Too Many Requests response")
    void testGetWithStatus429() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(429));

        HttpResponse response = client.getWithStatus(server.url("/api").toString(), Map.of());

        assertTrue(response.isRateLimited());
    }

    @Test
    @DisplayName("Should detect 500 server error response")
    void testGetWithStatus500() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(500).setBody("Internal Server Error"));

        HttpResponse response = client.getWithStatus(server.url("/api").toString(), Map.of());

        assertTrue(response.isServerError());
        assertFalse(response.isSuccess());
    }

    // -------------------------------------------------------------------------
    // POST
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should make POST request with JSON body")
    void testPost() throws Exception {
        server.enqueue(new MockResponse().setBody("{\"id\":1}").setResponseCode(201));

        String response = client.post(server.url("/api/users").toString(),
                Map.of(), "application/json", "{\"name\":\"test\"}");

        assertNotNull(response);
        RecordedRequest recorded = server.takeRequest();
        assertEquals("POST", recorded.getMethod());
        assertTrue(recorded.getHeader("Content-Type").contains("application/json"));
        assertEquals("{\"name\":\"test\"}", recorded.getBody().readUtf8());
    }

    @Test
    @DisplayName("Should return HttpResponse for postWithStatus")
    void testPostWithStatus() throws Exception {
        server.enqueue(new MockResponse().setBody("{\"created\":true}").setResponseCode(201));

        HttpResponse response = client.postWithStatus(server.url("/api/users").toString(),
                Map.of(), "application/json", "{\"name\":\"test\"}");

        assertEquals(201, response.getStatusCode());
        assertTrue(response.isSuccess());
        RecordedRequest recorded = server.takeRequest();
        assertEquals("POST", recorded.getMethod());
    }

    // -------------------------------------------------------------------------
    // PUT
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should make PUT request with body")
    void testPutWithStatus() throws Exception {
        server.enqueue(new MockResponse().setBody("{\"updated\":true}").setResponseCode(200));

        HttpResponse response = client.putWithStatus(server.url("/api/users/1").toString(),
                Map.of(), "application/json", "{\"name\":\"updated\"}");

        assertEquals(200, response.getStatusCode());
        RecordedRequest recorded = server.takeRequest();
        assertEquals("PUT", recorded.getMethod());
    }

    // -------------------------------------------------------------------------
    // DELETE
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should make DELETE request")
    void testDeleteWithStatus() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(204));

        HttpResponse response = client.deleteWithStatus(server.url("/api/users/1").toString(), Map.of());

        assertEquals(204, response.getStatusCode());
        RecordedRequest recorded = server.takeRequest();
        assertEquals("DELETE", recorded.getMethod());
    }

    // -------------------------------------------------------------------------
    // PATCH
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should make PATCH request with body")
    void testPatchWithStatus() throws Exception {
        server.enqueue(new MockResponse().setBody("{\"patched\":true}").setResponseCode(200));

        HttpResponse response = client.patchWithStatus(server.url("/api/users/1").toString(),
                Map.of(), "application/json", "{\"status\":\"active\"}");

        assertEquals(200, response.getStatusCode());
        RecordedRequest recorded = server.takeRequest();
        assertEquals("PATCH", recorded.getMethod());
    }

    // -------------------------------------------------------------------------
    // Headers
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should include custom per-request headers")
    void testCustomRequestHeaders() throws Exception {
        server.enqueue(new MockResponse().setBody("{}").setResponseCode(200));

        client.getWithStatus(server.url("/api").toString(),
                Map.of("X-Custom-Header", "custom-value", "Authorization", "Bearer token123"));

        RecordedRequest recorded = server.takeRequest();
        assertEquals("custom-value", recorded.getHeader("X-Custom-Header"));
        assertEquals("Bearer token123", recorded.getHeader("Authorization"));
    }

    @Test
    @DisplayName("Should include default headers from ScanConfig")
    void testDefaultConfigHeaders() throws Exception {
        config.addHeader("Authorization", "Bearer default-token");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setBody("{}").setResponseCode(200));

        client.get(server.url("/api").toString(), Map.of());

        RecordedRequest recorded = server.takeRequest();
        assertEquals("Bearer default-token", recorded.getHeader("Authorization"));
    }

    @Test
    @DisplayName("Should expose response headers")
    void testResponseHeaders() throws Exception {
        server.enqueue(new MockResponse()
                .setBody("{}")
                .setResponseCode(200)
                .addHeader("X-Rate-Limit", "100")
                .addHeader("Content-Type", "application/json"));

        HttpResponse response = client.getWithStatus(server.url("/api").toString(), Map.of());

        assertNotNull(response.getHeader("X-Rate-Limit"));
        assertEquals("100", response.getHeader("X-Rate-Limit"));
        assertTrue(response.hasHeader("Content-Type"));
    }

    // -------------------------------------------------------------------------
    // *NoAuth variants — must actually suppress the configured bearer token / API key,
    // not just skip adding extra headers. Regression coverage for the bug where a plain
    // Map.of() additional-headers map still carried the configured default Authorization
    // header, breaking every "endpoint actually requires auth" baseline probe.
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("getWithStatusNoAuth should omit the configured bearer token")
    void testGetWithStatusNoAuthOmitsBearerToken() throws Exception {
        config.setBearerToken("secret-token");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(401));

        client.getWithStatusNoAuth(server.url("/api/secure").toString());

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("Authorization"),
                "getWithStatusNoAuth must not send the configured Authorization header");
    }

    @Test
    @DisplayName("getWithStatus (non-NoAuth) still sends the configured bearer token with an empty headers map")
    void testGetWithStatusStillSendsBearerTokenByDefault() throws Exception {
        config.setBearerToken("secret-token");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(200));

        client.getWithStatus(server.url("/api/secure").toString(), Map.of());

        RecordedRequest recorded = server.takeRequest();
        assertEquals("Bearer secret-token", recorded.getHeader("Authorization"),
                "existing behavior for non-NoAuth calls must be unchanged");
    }

    @Test
    @DisplayName("postWithStatusNoAuth should omit the configured bearer token")
    void testPostWithStatusNoAuthOmitsBearerToken() throws Exception {
        config.setBearerToken("secret-token");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(401));

        client.postWithStatusNoAuth(server.url("/api/secure").toString(), "application/json", "{}");

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("Authorization"));
        assertEquals("POST", recorded.getMethod());
    }

    @Test
    @DisplayName("putWithStatusNoAuth should omit the configured bearer token")
    void testPutWithStatusNoAuthOmitsBearerToken() throws Exception {
        config.setBearerToken("secret-token");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(401));

        client.putWithStatusNoAuth(server.url("/api/secure").toString(), "application/json", "{}");

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("Authorization"));
        assertEquals("PUT", recorded.getMethod());
    }

    @Test
    @DisplayName("deleteWithStatusNoAuth should omit the configured bearer token")
    void testDeleteWithStatusNoAuthOmitsBearerToken() throws Exception {
        config.setBearerToken("secret-token");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(401));

        client.deleteWithStatusNoAuth(server.url("/api/secure").toString());

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("Authorization"));
        assertEquals("DELETE", recorded.getMethod());
    }

    @Test
    @DisplayName("getNoAuth should omit the configured bearer token")
    void testGetNoAuthOmitsBearerToken() throws Exception {
        config.setBearerToken("secret-token");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(401).setBody("nope"));

        client.getNoAuth(server.url("/api/secure").toString());

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("Authorization"));
    }

    @Test
    @DisplayName("getWithStatusNoAuth should also omit a configured API key header")
    void testGetWithStatusNoAuthOmitsApiKeyHeader() throws Exception {
        config.setApiKey("secret-api-key");
        config.setApiKeyHeader("X-API-Key");
        config.addHeader("X-API-Key", "secret-api-key");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(401));

        client.getWithStatusNoAuth(server.url("/api/secure").toString());

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("X-API-Key"),
                "getWithStatusNoAuth must not send the configured API key header either");
    }

    @Test
    @DisplayName("getWithStatusNoAuth must not let a configured Basic Auth authenticator silently reattach credentials on 401")
    void testGetWithStatusNoAuthNotReauthenticatedByBasicAuthAuthenticator() throws Exception {
        // Regression for a bug found reviewing this same fix: suppressing the default
        // Authorization header when BUILDING the request isn't enough on its own — OkHttp's
        // Authenticator (registered whenever --username/--password is configured) fires
        // automatically on ANY 401 response, regardless of which headers the original request
        // carried, and transparently retries with "Authorization: Basic ..." attached. A client
        // that only strips the header at request-build time but still uses the same
        // authenticator-bearing OkHttpClient to execute it would see this second, authenticated
        // request's response instead of the genuine unauthenticated 401 — silently reintroducing
        // the exact false-positive/false-negative bug this class's *NoAuth methods exist to fix.
        config.setBasicAuthUsername("admin");
        config.setBasicAuthPassword("hunter2");
        client = new HttpClient(config);

        // First response: 401 with a challenge, which is what triggers OkHttp's Authenticator.
        server.enqueue(new MockResponse().setResponseCode(401)
                .addHeader("WWW-Authenticate", "Basic realm=\"test\""));
        // If the authenticator fires and retries, this second, authenticated-looking response
        // would be served instead — the assertion below must NOT see this 200.
        server.enqueue(new MockResponse().setResponseCode(200).setBody("[]"));

        HttpResponse response = client.getWithStatusNoAuth(server.url("/api/secure").toString());

        assertEquals(401, response.getStatusCode(),
                "getWithStatusNoAuth must return the genuine 401 baseline, not a response from " +
                "an automatic Basic-Auth retry");
        assertEquals(1, server.getRequestCount(),
                "Only one request should have been sent — the authenticator must not have retried");
    }

    @Test
    @DisplayName("Non-NoAuth requests still get Basic Auth's automatic 401-retry behavior (existing behavior unchanged)")
    void testGetWithStatusStillReauthenticatedByBasicAuthAuthenticatorWhenNotUsingNoAuthVariant() throws Exception {
        config.setBasicAuthUsername("admin");
        config.setBasicAuthPassword("hunter2");
        client = new HttpClient(config);

        server.enqueue(new MockResponse().setResponseCode(401)
                .addHeader("WWW-Authenticate", "Basic realm=\"test\""));
        server.enqueue(new MockResponse().setResponseCode(200).setBody("[]"));

        HttpResponse response = client.getWithStatus(server.url("/api/secure").toString(), Map.of());

        assertEquals(200, response.getStatusCode(),
                "Regular (non-NoAuth) requests should still benefit from automatic Basic Auth retry");
        assertEquals(2, server.getRequestCount(), "The authenticator should have retried once");
    }

    @Test
    @DisplayName("getWithStatusNoAuth must not send a session cookie captured earlier in the scan")
    void testGetWithStatusNoAuthDoesNotSendEarlierSessionCookie() throws Exception {
        // Regression: noAuthClient must not share the authenticated client's CookieJar. A cookie
        // captured from an earlier authenticated request (e.g. a login test case) is an implicit
        // credential just like a bearer token — a genuine no-auth baseline must not carry it.
        server.enqueue(new MockResponse().setResponseCode(200)
                .addHeader("Set-Cookie", "session=abc123; Path=/"));
        client.getWithStatus(server.url("/login").toString(), Map.of());
        server.takeRequest(); // drain the login request

        server.enqueue(new MockResponse().setResponseCode(401));
        client.getWithStatusNoAuth(server.url("/api/secure").toString());

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("Cookie"),
                "getWithStatusNoAuth must not send a session cookie captured by an earlier request");
    }

    @Test
    @DisplayName("getWithStatusNoAuth sends configured protocol headers but no other custom header")
    void testGetWithStatusNoAuthKeepsOnlyProtocolDefaultHeaders() throws Exception {
        config.setBearerToken("secret-token");
        config.addHeader("X-Custom-Static-Header", "drop-me");
        config.addHeader("Accept", "application/json");
        config.addHeader("Accept-Encoding", "identity");
        client = new HttpClient(config);
        server.enqueue(new MockResponse().setResponseCode(401));

        client.getWithStatusNoAuth(server.url("/api/secure").toString());

        RecordedRequest recorded = server.takeRequest();
        assertNull(recorded.getHeader("Authorization"));
        assertNull(recorded.getHeader("X-Custom-Static-Header"),
                "a user-configured custom header may identify the user, so a NoAuth request leaves it off");
        assertEquals("application/json", recorded.getHeader("Accept"));
        assertEquals("identity", recorded.getHeader("Accept-Encoding"));
    }

    // -------------------------------------------------------------------------
    // Miscellaneous
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should return target URL from config")
    void testGetTargetUrl() {
        assertEquals(server.url("/").toString(), client.getTargetUrl());
    }

    @Test
    @DisplayName("Should handle async request and invoke success callback")
    void testAsyncRequest() throws InterruptedException {
        server.enqueue(new MockResponse().setBody("{\"async\":true}").setResponseCode(200));

        CountDownLatch latch = new CountDownLatch(1);
        AtomicInteger capturedStatus = new AtomicInteger();
        AtomicBoolean successCalled = new AtomicBoolean(false);

        client.asyncRequest(server.url("/api").toString(), "GET", Map.of(), null, null,
                new HttpClient.HttpResponseCallback() {
                    @Override
                    public void onSuccess(int statusCode, java.util.Map<String, java.util.List<String>> headers, String body) {
                        capturedStatus.set(statusCode);
                        successCalled.set(true);
                        latch.countDown();
                    }

                    @Override
                    public void onFailure(IOException e) { latch.countDown(); }

                    @Override
                    public void onFailure(Exception e) { latch.countDown(); }
                });

        assertTrue(latch.await(5, TimeUnit.SECONDS), "Async callback should fire within 5 seconds");
        assertTrue(successCalled.get());
        assertEquals(200, capturedStatus.get());
    }

    // -------------------------------------------------------------------------
    // Basic Auth authenticator
    // -------------------------------------------------------------------------

    private HttpClient basicAuthClient() {
        ScanConfig c = new ScanConfig();
        c.setTargetUrl(server.url("/").toString());
        c.setBasicAuthUsername("user");
        c.setBasicAuthPassword("pass");
        return new HttpClient(c);
    }

    @Test
    @DisplayName("Basic Auth should not replace an explicit Authorization header on 401")
    void testBasicAuthDoesNotReplaceExplicitAuthorization() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(401));
        server.enqueue(new MockResponse().setResponseCode(200));

        HttpResponse response = basicAuthClient().getWithStatus(server.url("/api/x").toString(),
                Map.of("Authorization", "Bearer forged"));

        assertEquals(401, response.getStatusCode());
        assertEquals(1, server.getRequestCount());
        assertEquals("Bearer forged", server.takeRequest().getHeader("Authorization"));
    }

    @Test
    @DisplayName("Basic Auth should retry at most once against an always-401 server")
    void testBasicAuthRetriesAtMostOnce() throws Exception {
        for (int i = 0; i < 30; i++) {
            server.enqueue(new MockResponse().setResponseCode(401));
        }

        HttpResponse response = basicAuthClient().getWithStatus(server.url("/api/x").toString(), Map.of());

        assertEquals(401, response.getStatusCode());
        assertTrue(server.getRequestCount() <= 2, "requests: " + server.getRequestCount());
    }

    @Test
    @DisplayName("Basic Auth credentials should not be sent to a different host after a redirect")
    void testBasicAuthNotForwardedAfterRedirect() throws Exception {
        MockWebServer other = new MockWebServer();
        other.start();
        try {
            other.enqueue(new MockResponse().setResponseCode(401));
            other.enqueue(new MockResponse().setResponseCode(200));
            server.enqueue(new MockResponse().setResponseCode(302)
                    .setHeader("Location", other.url("/stolen").toString()));

            HttpResponse response = basicAuthClient().getWithStatus(server.url("/api/x").toString(), Map.of());

            assertEquals(401, response.getStatusCode());
            assertEquals(1, other.getRequestCount());
            assertNull(other.takeRequest().getHeader("Authorization"));
        } finally {
            other.shutdown();
        }
    }

    @Test
    @DisplayName("Basic Auth should succeed against a server that challenges once")
    void testBasicAuthSucceedsAfterChallenge() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(401).setHeader("WWW-Authenticate", "Basic realm=\"t\""));
        server.enqueue(new MockResponse().setResponseCode(200).setBody("ok"));

        HttpResponse response = basicAuthClient().getWithStatus(server.url("/api/x").toString(), Map.of());

        assertEquals(200, response.getStatusCode());
        assertEquals(2, server.getRequestCount());
        server.takeRequest();
        assertEquals("Basic dXNlcjpwYXNz", server.takeRequest().getHeader("Authorization"));
    }
}
