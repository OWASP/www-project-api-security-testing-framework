package org.owasp.astf.core.discovery;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@DisplayName("EndpointDiscoveryService Tests")
class EndpointDiscoveryServiceTest {

    @Mock
    private HttpClient httpClient;

    private ScanConfig config;
    private EndpointDiscoveryService discoveryService;

    private static HttpResponse ok(String body) {
        return new HttpResponse(200, body, Map.of());
    }

    private static HttpResponse notFound() {
        return new HttpResponse(404, "Not Found", Map.of());
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        config = new ScanConfig();
        config.setTargetUrl("https://api.example.com");
        discoveryService = new EndpointDiscoveryService(config, httpClient);
    }

    @Test
    @DisplayName("Should parse Swagger 2.0 specification and return endpoints")
    void testDiscoverFromSwagger2Spec() throws IOException {
        String swagger = """
                {
                  "swagger": "2.0",
                  "paths": {
                    "/users": {"get": {}, "post": {}},
                    "/users/{id}": {"get": {}, "put": {}, "delete": {}}
                  }
                }
                """;

        // All spec path probes return the swagger JSON
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(ok(swagger));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should discover endpoints from Swagger 2.0 spec");
        assertTrue(endpoints.stream().anyMatch(e -> "/users".equals(e.getPath())),
                "Should contain /users path");
        assertTrue(endpoints.stream().anyMatch(e -> "GET".equals(e.getMethod())
                        && "/users".equals(e.getPath())),
                "Should contain GET /users");
    }

    @Test
    @DisplayName("Should parse OpenAPI 3.x specification and return endpoints")
    void testDiscoverFromOpenApi3Spec() throws IOException {
        String openApi = """
                {
                  "openapi": "3.0.0",
                  "paths": {
                    "/api/products": {
                      "get": {"security": [{"bearerAuth": []}]},
                      "post": {}
                    }
                  }
                }
                """;

        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(ok(openApi));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty());
        assertTrue(endpoints.stream().anyMatch(e ->
                        "/api/products".equals(e.getPath()) && "GET".equals(e.getMethod())),
                "Should contain GET /api/products");
        // GET has security requirement -> requiresAuthentication should be true
        assertTrue(endpoints.stream()
                        .filter(e -> "/api/products".equals(e.getPath()) && "GET".equals(e.getMethod()))
                        .findFirst()
                        .map(EndpointInfo::isRequiresAuthentication)
                        .orElse(false),
                "Endpoint with security requirement should have requiresAuthentication=true");
    }

    @Test
    @DisplayName("Should return fallback endpoints when no spec is found and discovery fails")
    void testFallbackEndpointsOnEmptyResponse() throws IOException {
        // All HTTP calls return empty — simulates no spec and no reachable endpoints
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(ok(""));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should return fallback endpoints");
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().contains("/api/v1/users")),
                "Fallback should include common user endpoint");
    }

    @Test
    @DisplayName("Should return fallback endpoints when HTTP calls throw exceptions")
    void testFallbackEndpointsOnException() throws IOException {
        when(httpClient.getWithStatus(anyString(), anyMap())).thenThrow(new IOException("Connection refused"));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should return fallback endpoints on network error");
    }

    @Test
    @DisplayName("Should discover endpoints from reachable API roots")
    void testDiscoverFromApiRoot() throws IOException {
        // Spec paths return empty, but the /api root returns a non-empty JSON response
        when(httpClient.getWithStatus(anyString(), anyMap())).thenAnswer(inv -> {
            String url = inv.getArgument(0);
            if (url.contains("swagger") || url.contains("openapi") || url.contains("api-docs")) {
                return ok("");
            }
            if (url.endsWith("/api")) {
                return ok("{\"links\":[]}");
            }
            return ok("");
        });

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        // /api was reachable — should at least have added it
        assertFalse(endpoints.isEmpty());
    }

    @Test
    @DisplayName("Should not throw when spec JSON is malformed")
    void testMalformedSpecJson() throws IOException {
        String malformedJson = "{invalid json content}";
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(ok(malformedJson));

        assertDoesNotThrow(() -> discoveryService.discoverEndpoints());
    }

    @Test
    @DisplayName("Should not mistake a non-empty 404 error page for a real API root (regression)")
    void testDoesNotTreat404PageAsDiscoveredEndpoint() throws IOException {
        // Reproduces the crAPI false-discovery bug: every generic path guess reached a real
        // web server that replied with a non-empty 404 page (a very common server behavior).
        // A body-emptiness-only check would misread every single one of these as "found".
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(notFound());

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        // Discovery should fall back to the honest hardcoded fallback list rather than
        // reporting any of the generic /api, /api/v1, /rest, ... guesses as real endpoints.
        assertTrue(endpoints.stream().noneMatch(e -> "/api".equals(e.getPath())),
                "A 404 response for /api should not be reported as a discovered endpoint");
        assertTrue(endpoints.stream().noneMatch(e -> "/rest".equals(e.getPath())),
                "A 404 response for /rest should not be reported as a discovered endpoint");
        assertFalse(endpoints.isEmpty(), "Should still return the fallback endpoint list");
    }

    @Test
    @DisplayName("Should not fabricate endpoints when every guessed path hits an SPA catch-all (regression)")
    void testDoesNotFabricateEndpointsFromHtmlCatchAll() throws IOException {
        // A reverse proxy / SPA answers 200 text/html with the app shell for every path. Gating
        // on the status code alone reads all 8 root guesses and all 8x19 resource guesses as
        // real, fabricating hundreds of endpoints that every test case then re-tests.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "<html><body><div id=\"root\"></div></body></html>",
                        Map.of("Content-Type", List.of("text/html"))));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertTrue(endpoints.stream().noneMatch(e -> "/api".equals(e.getPath())),
                "An app shell served for /api is not a discovered API root");
        assertTrue(endpoints.stream().noneMatch(e -> "/rest".equals(e.getPath())),
                "An app shell served for /rest is not a discovered API root");
        assertTrue(endpoints.stream().noneMatch(e -> e.getPath().startsWith("/rest/")),
                "No /rest/<resource> endpoint should be fabricated from a catch-all response");
        assertFalse(endpoints.isEmpty(), "Should still fall back to the honest hardcoded list");
    }

    @Test
    @DisplayName("Should not fabricate endpoints when a gateway answers 200 with a JSON not-found envelope (regression)")
    void testDoesNotFabricateEndpointsFromJsonCatchAll() throws IOException {
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"message\":\"Not Found\"}",
                        Map.of("Content-Type", List.of("application/json"))));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertTrue(endpoints.stream().noneMatch(e -> "/api".equals(e.getPath())),
                "A 200 'Not Found' envelope is not a discovered API root");
        assertTrue(endpoints.stream().noneMatch(e -> e.getPath().startsWith("/service/")),
                "No /service/<resource> endpoint should be fabricated from a catch-all response");
        assertFalse(endpoints.isEmpty(), "Should still fall back to the honest hardcoded list");
    }

    @Test
    @DisplayName("Should still discover a real API root on a catch-all target (no false negative)")
    void testStillDiscoversRealRootOnCatchAllTarget() throws IOException {
        // Everything is the catch-all except /api, which serves a genuinely different payload.
        when(httpClient.getWithStatus(anyString(), anyMap())).thenAnswer(inv -> {
            String url = inv.getArgument(0);
            if (url.endsWith("/api")) {
                return new HttpResponse(200, "{\"links\":[{\"rel\":\"users\",\"href\":\"/api/users\"}]}",
                        Map.of("Content-Type", List.of("application/json")));
            }
            return new HttpResponse(200, "{\"success\":false,\"data\":null}",
                    Map.of("Content-Type", List.of("application/json")));
        });

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertTrue(endpoints.stream().anyMatch(e -> "/api".equals(e.getPath())),
                "A root whose response differs from the catch-all must still be discovered");
    }

    @Test
    @DisplayName("Should exclude non-HTTP-method fields from OpenAPI paths")
    void testExcludesNonMethodFieldsFromSpec() throws IOException {
        String openApi = """
                {
                  "openapi": "3.0.0",
                  "paths": {
                    "/items": {
                      "get": {},
                      "summary": "Item operations",
                      "parameters": []
                    }
                  }
                }
                """;
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(ok(openApi));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        // Only GET should be extracted; "summary" and "parameters" are not HTTP methods
        long itemEndpoints = endpoints.stream()
                .filter(e -> "/items".equals(e.getPath()))
                .count();
        assertEquals(1, itemEndpoints, "Only the GET method should be extracted for /items");
    }
}
