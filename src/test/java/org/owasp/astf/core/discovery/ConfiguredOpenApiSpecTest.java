package org.owasp.astf.core.discovery;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ConfigLoader;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/** The openApiSpec setting (--openapi): an http(s) URL or a local file (JSON or YAML). */
@DisplayName("Custom OpenAPI specification (--openapi)")
class ConfiguredOpenApiSpecTest {

    private static final String JSON_SPEC = """
            {"openapi":"3.0.0","paths":{"/widgets":{"get":{}},"/widgets/{id}":{"delete":{}}}}
            """;

    private static final String YAML_SPEC = """
            openapi: 3.0.0
            paths:
              /gadgets:
                get: {}
              /gadgets/{id}:
                put: {}
            """;

    private MockWebServer target;
    private MockWebServer specHost;
    @TempDir
    Path tmp;

    @BeforeEach
    void setUp() throws Exception {
        target = new MockWebServer();
        specHost = new MockWebServer();
        target.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if ("/docs/custom-spec.json".equals(request.getPath())) {
                    return new MockResponse().setBody(JSON_SPEC);
                }
                return new MockResponse().setResponseCode(404).setBody("Not Found");
            }
        });
        specHost.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setBody(JSON_SPEC);
            }
        });
        target.start();
        specHost.start();
    }

    @AfterEach
    void tearDown() throws Exception {
        target.shutdown();
        specHost.shutdown();
    }

    private ScanConfig config() {
        ScanConfig config = new ScanConfig();
        config.setTargetUrl("http://" + target.getHostName() + ":" + target.getPort());
        return config;
    }

    private static boolean has(List<EndpointInfo> endpoints, String method, String path) {
        return endpoints.stream().anyMatch(e -> e.getMethod().equals(method) && e.getPath().equals(path));
    }

    @Test
    @DisplayName("A local JSON file is read, and the target is not asked for a spec at all")
    void localJsonFile() throws Exception {
        Path file = Files.writeString(tmp.resolve("spec.json"), JSON_SPEC);
        ScanConfig config = config();
        config.setOpenApiSpec(file.toString());

        List<EndpointInfo> endpoints = new EndpointDiscoveryService(config, new HttpClient(config)).discoverEndpoints();

        assertEquals(2, endpoints.size(), endpoints.toString());
        assertTrue(has(endpoints, "GET", "/widgets"));
        assertTrue(has(endpoints, "DELETE", "/widgets/{id}"));
        assertEquals(0, target.getRequestCount(), "a local file needs no request to the target");
    }

    @Test
    @DisplayName("A local YAML file is read")
    void localYamlFile() throws Exception {
        Path file = Files.writeString(tmp.resolve("spec.yaml"), YAML_SPEC);
        ScanConfig config = config();
        config.setOpenApiSpec(file.toString());

        List<EndpointInfo> endpoints = new EndpointDiscoveryService(config, new HttpClient(config)).discoverEndpoints();

        assertEquals(2, endpoints.size(), endpoints.toString());
        assertTrue(has(endpoints, "GET", "/gadgets"));
        assertTrue(has(endpoints, "PUT", "/gadgets/{id}"));
    }

    @Test
    @DisplayName("A URL on another host is fetched without Authorization, API key, custom headers or cookies")
    void urlOnAnotherHostGetsNoCredentials() throws Exception {
        ScanConfig config = config();
        config.setBearerToken("primary-secret");
        config.setApiKey("key-secret");
        config.addHeader("X-API-Key", "key-secret");
        config.addHeader("X-Tenant-Secret", "custom-secret");
        config.addHeader("Cookie", "sid=cookie-secret");
        config.setOpenApiSpec(specHost.url("/anything.json").toString());

        List<EndpointInfo> endpoints = new EndpointDiscoveryService(config, new HttpClient(config)).discoverEndpoints();

        RecordedRequest fetch = specHost.takeRequest(5, TimeUnit.SECONDS);
        assertNotNull(fetch, "the spec must still be fetched");
        assertNull(fetch.getHeader("Authorization"));
        assertNull(fetch.getHeader("X-API-Key"));
        assertNull(fetch.getHeader("X-Tenant-Secret"));
        assertNull(fetch.getHeader("Cookie"));
        assertTrue(has(endpoints, "GET", "/widgets"), endpoints.toString());
    }

    @Test
    @DisplayName("A spec URL on the target's own host gets the scan's credentials")
    void urlOnTargetGetsCredentials() throws Exception {
        ScanConfig config = config();
        config.setBearerToken("primary-secret");
        config.setOpenApiSpec(target.url("/docs/custom-spec.json").toString());

        new EndpointDiscoveryService(config, new HttpClient(config)).discoverEndpoints();

        RecordedRequest fetch = target.takeRequest(5, TimeUnit.SECONDS);
        assertEquals("Bearer primary-secret", fetch.getHeader("Authorization"));
    }

    @Test
    @DisplayName("A spec that is missing falls back to automatic discovery, so the target is still scanned")
    void missingFileFallsBackToDiscovery() throws Exception {
        ScanConfig config = config();
        config.setOpenApiSpec(tmp.resolve("does-not-exist.json").toString());

        List<EndpointInfo> endpoints = new EndpointDiscoveryService(config, new HttpClient(config)).discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "discovery must still produce endpoints to test");
        assertTrue(target.getRequestCount() > 0, "automatic discovery must have probed the target");
    }

    @Test
    @DisplayName("A file that is not an OpenAPI document falls back to automatic discovery")
    void notASpecFallsBackToDiscovery() throws Exception {
        Path file = Files.writeString(tmp.resolve("other.json"), "{\"hello\":\"world\"}");
        ScanConfig config = config();
        config.setOpenApiSpec(file.toString());

        List<EndpointInfo> endpoints = new EndpointDiscoveryService(config, new HttpClient(config)).discoverEndpoints();

        assertFalse(endpoints.isEmpty());
        assertTrue(target.getRequestCount() > 0);
    }

    @Test
    @DisplayName("With discovery disabled, an unreadable spec yields no endpoints rather than guessed ones")
    void missingFileWithDiscoveryDisabled() throws Exception {
        ScanConfig config = config();
        config.setDiscoveryEnabled(false);
        config.setOpenApiSpec(tmp.resolve("does-not-exist.json").toString());

        List<EndpointInfo> endpoints = new EndpointDiscoveryService(config, new HttpClient(config)).discoverEndpoints();

        assertTrue(endpoints.isEmpty());
        assertEquals(0, target.getRequestCount());
    }

    @Test
    @DisplayName("An explicit spec is used even with --no-discovery, and every endpoint in it is scanned")
    void scannerUsesSpecWithDiscoveryDisabled() throws Exception {
        Path file = Files.writeString(tmp.resolve("spec.json"), JSON_SPEC);
        ScanConfig config = config();
        config.setDiscoveryEnabled(false);
        config.setOpenApiSpec(file.toString());
        config.setTimeoutMinutes(2);

        new Scanner(config).scan();

        boolean sawWidgets = false;
        RecordedRequest r;
        while ((r = target.takeRequest(1, TimeUnit.SECONDS)) != null) {
            if (r.getPath() != null && r.getPath().startsWith("/widgets")) {
                sawWidgets = true;
            }
        }
        assertTrue(sawWidgets, "the scanner must test the endpoints listed in the spec");
    }

    @Test
    @DisplayName("The openApiSpec key is read from a config file")
    void configFileKey() throws Exception {
        Path cfg = Files.writeString(tmp.resolve("scan.yaml"),
                "targetUrl: \"https://api.example.com\"\nopenApiSpec: \"./specs/api.yaml\"\n");

        ScanConfig loaded = new ConfigLoader().loadFromFile(cfg.toString());

        assertEquals("./specs/api.yaml", loaded.getOpenApiSpec());
    }
}
