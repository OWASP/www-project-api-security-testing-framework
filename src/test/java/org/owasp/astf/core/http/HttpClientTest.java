package org.owasp.astf.core.http;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;

import java.io.IOException;
import java.util.Map;
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
}
