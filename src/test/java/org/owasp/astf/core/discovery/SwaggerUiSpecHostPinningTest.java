package org.owasp.astf.core.discovery;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * A Swagger UI page on the target can name a spec URL on another host. Discovery must still
 * fetch and use that spec, but without the scan's credentials.
 */
@DisplayName("Swagger UI spec fetch keeps credentials on the target")
class SwaggerUiSpecHostPinningTest {

    private MockWebServer target;
    private MockWebServer specHost;

    @BeforeEach
    void setUp() throws Exception {
        target = new MockWebServer();
        specHost = new MockWebServer();
        target.start();
        specHost.start();

        String specUrl = specHost.url("/openapi.json").toString();
        target.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (request.getPath() != null && request.getPath().endsWith("/swagger/v1/swagger.json")) {
                    return new MockResponse().setBody("<html><script>SwaggerUIBundle({ url: '"
                            + specUrl + "' })</script> swagger</html>");
                }
                return new MockResponse().setResponseCode(404);
            }
        });
        specHost.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setHeader("Content-Type", "application/json").setBody("""
                        {"openapi":"3.0.0","paths":{"/widgets":{"get":{}}}}
                        """);
            }
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        target.shutdown();
        specHost.shutdown();
    }

    @Test
    @DisplayName("Spec on another host is fetched without Authorization, API key, custom headers or cookies")
    void offHostSpecFetchedWithoutCredentials() throws Exception {
        ScanConfig config = new ScanConfig();
        config.setTargetUrl("http://" + target.getHostName() + ":" + target.getPort());
        config.setBearerToken("primary-secret");
        config.setApiKey("key-secret");
        config.addHeader("X-API-Key", "key-secret");
        config.addHeader("X-Tenant-Secret", "custom-secret");
        config.addHeader("Cookie", "sid=cookie-secret");

        List<EndpointInfo> endpoints = new EndpointDiscoveryService(config, new HttpClient(config))
                .discoverEndpoints();

        RecordedRequest specFetch = specHost.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(specFetch, "the spec on the other host must still be fetched");
        assertNull(specFetch.getHeader("Authorization"));
        assertNull(specFetch.getHeader("X-API-Key"));
        assertNull(specFetch.getHeader("X-Tenant-Secret"));
        assertNull(specFetch.getHeader("Cookie"));

        assertFalse(endpoints.isEmpty());
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().equals("/widgets")),
                "endpoints from the off-host spec must still be discovered");

        RecordedRequest uiFetch = target.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(uiFetch.getHeader("Authorization"), "the target itself still gets credentials");
    }
}
