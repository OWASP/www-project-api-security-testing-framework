package org.owasp.astf.core.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Credentials must stay on the target: a request that ends up on another host:port (through a
 * redirect or a direct call) is still sent, but without any credential the scan was given.
 */
@DisplayName("HttpClient host pinning")
class HttpClientHostPinningTest {

    private MockWebServer target;
    private MockWebServer other;
    private ScanConfig config;

    @BeforeEach
    void setUp() throws Exception {
        target = new MockWebServer();
        other = new MockWebServer();
        target.start();
        other.start();
        config = new ScanConfig();
        config.setTargetUrl(target.url("/").toString());
        config.setBearerToken("primary-secret");
        config.setApiKey("key-secret");
        config.setApiKeyHeader("X-Api-Token");
        config.addHeader("X-Api-Token", "key-secret");
        config.addHeader("X-Session-Id", "custom-secret");
        config.addHeader("Cookie", "sid=user-cookie-secret");
    }

    @AfterEach
    void tearDown() throws Exception {
        target.shutdown();
        other.shutdown();
    }

    private void assertNoCredentials(RecordedRequest r) {
        assertNull(r.getHeader("Authorization"), "Authorization leaked to " + r.getRequestUrl());
        assertNull(r.getHeader("X-Api-Token"), "API key leaked to " + r.getRequestUrl());
        assertNull(r.getHeader("X-Session-Id"), "custom header leaked to " + r.getRequestUrl());
        assertNull(r.getHeader("Cookie"), "cookie leaked to " + r.getRequestUrl());
    }

    private void assertAllCredentials(RecordedRequest r) {
        assertEquals("Bearer primary-secret", r.getHeader("Authorization"));
        assertEquals("key-secret", r.getHeader("X-Api-Token"));
        assertEquals("custom-secret", r.getHeader("X-Session-Id"));
        assertNotNull(r.getHeader("Cookie"));
    }

    @Test
    @DisplayName("Redirect to another host: request still made, no credentials or cookies sent")
    void crossHostRedirectStripsCredentials() throws Exception {
        target.enqueue(new MockResponse().setResponseCode(302)
                .addHeader("Location", other.url("/landing"))
                .addHeader("Set-Cookie", "jar=target-jar-secret; Path=/"));
        other.enqueue(new MockResponse().setBody("other"));

        HttpResponse response = new HttpClient(config).getWithStatus(target.url("/start").toString(), Map.of());

        assertEquals(200, response.getStatusCode());
        assertEquals("other", response.getBody());
        RecordedRequest first = target.takeRequest(5, TimeUnit.SECONDS);
        assertAllCredentials(first);
        RecordedRequest hop = other.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(hop, "redirect target must still be requested");
        assertEquals("/landing", hop.getPath());
        assertNoCredentials(hop);
    }

    @Test
    @DisplayName("Per-request Authorization and custom headers are also stripped after a cross-host redirect")
    void crossHostRedirectStripsPerRequestCredentials() throws Exception {
        target.enqueue(new MockResponse().setResponseCode(307).addHeader("Location", other.url("/x")));
        other.enqueue(new MockResponse().setBody("ok"));

        new HttpClient(config).postWithStatus(target.url("/p").toString(),
                Map.of("Authorization", "Bearer forged", "X-Session-Id", "per-request"),
                "application/json", "{}");

        target.takeRequest(5, TimeUnit.SECONDS);
        RecordedRequest hop = other.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(hop);
        assertEquals("POST", hop.getMethod());
        assertNoCredentials(hop);
    }

    @Test
    @DisplayName("Same-host redirect keeps credentials")
    void sameHostRedirectKeepsCredentials() throws Exception {
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", "/next"));
        target.enqueue(new MockResponse().setBody("done"));

        HttpResponse response = new HttpClient(config).getWithStatus(target.url("/start").toString(), Map.of());

        assertEquals("done", response.getBody());
        target.takeRequest(5, TimeUnit.SECONDS);
        RecordedRequest hop = target.takeRequest(5, TimeUnit.SECONDS);
        assertEquals("/next", hop.getPath());
        assertAllCredentials(hop);
    }

    @Test
    @DisplayName("A host listed in scopeHosts receives credentials")
    void scopeHostReceivesCredentials() throws Exception {
        config.setScopeHosts(List.of(other.getHostName() + ":" + other.getPort()));
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/landing")));
        other.enqueue(new MockResponse().setBody("other"));

        new HttpClient(config).getWithStatus(target.url("/start").toString(), Map.of());

        target.takeRequest(5, TimeUnit.SECONDS);
        RecordedRequest hop = other.takeRequest(5, TimeUnit.SECONDS);
        assertAllCredentials(hop);
    }

    @Test
    @DisplayName("A scopeHosts entry with a different port does not admit the host")
    void scopeHostWithOtherPortDoesNotMatch() throws Exception {
        config.setScopeHosts(List.of(other.getHostName() + ":" + (other.getPort() == 1 ? 2 : 1)));
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/landing")));
        other.enqueue(new MockResponse().setBody("other"));

        new HttpClient(config).getWithStatus(target.url("/start").toString(), Map.of());

        target.takeRequest(5, TimeUnit.SECONDS);
        assertNoCredentials(other.takeRequest(5, TimeUnit.SECONDS));
    }

    @Test
    @DisplayName("A direct request to another host is sent without credentials")
    void directOffTargetRequestStripsCredentials() throws Exception {
        other.enqueue(new MockResponse().setBody("x"));

        new HttpClient(config).get(other.url("/spec.json").toString(), Map.of());

        RecordedRequest r = other.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(r);
        assertNoCredentials(r);
    }

    @Test
    @DisplayName("Basic Auth is not sent to another host after a redirect")
    void basicAuthNotSentCrossHost() throws Exception {
        ScanConfig basic = new ScanConfig();
        basic.setTargetUrl(target.url("/").toString());
        basic.setBasicAuthUsername("u");
        basic.setBasicAuthPassword("p");
        basic.addHeader("Authorization", "Basic dTpw");
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/landing")));
        other.enqueue(new MockResponse().setResponseCode(401).addHeader("WWW-Authenticate", "Basic realm=x"));

        HttpResponse response = new HttpClient(basic).getWithStatus(target.url("/").toString(), Map.of());

        assertEquals(401, response.getStatusCode());
        target.takeRequest(5, TimeUnit.SECONDS);
        assertNull(other.takeRequest(5, TimeUnit.SECONDS).getHeader("Authorization"));
        assertEquals(1, other.getRequestCount());
    }

    @Test
    @DisplayName("followRedirects=false returns the redirect itself and does not follow it")
    void followRedirectsFalseStopsFollowing() throws Exception {
        config.setFollowRedirects(false);
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", other.url("/landing")));

        HttpResponse response = new HttpClient(config).getWithStatus(target.url("/start").toString(), Map.of());

        assertEquals(302, response.getStatusCode());
        assertEquals(0, other.getRequestCount());
    }

    @Test
    @DisplayName("followRedirects=false also applies to the no-auth variants")
    void followRedirectsFalseAppliesToNoAuth() throws Exception {
        config.setFollowRedirects(false);
        target.enqueue(new MockResponse().setResponseCode(301).addHeader("Location", "/elsewhere"));

        HttpResponse response = new HttpClient(config).getWithStatusNoAuth(target.url("/start").toString());

        assertEquals(301, response.getStatusCode());
        assertEquals(1, target.getRequestCount());
    }

    @Test
    @DisplayName("followRedirects defaults to true")
    void followRedirectsDefault() throws Exception {
        target.enqueue(new MockResponse().setResponseCode(302).addHeader("Location", "/next"));
        target.enqueue(new MockResponse().setBody("done"));

        HttpResponse response = new HttpClient(config).getWithStatus(target.url("/").toString(), Map.of());

        assertEquals(200, response.getStatusCode());
    }
}
