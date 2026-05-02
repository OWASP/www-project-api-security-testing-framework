package org.owasp.astf.core.discovery;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;

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
        when(httpClient.get(anyString(), anyMap())).thenReturn(swagger);

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

        when(httpClient.get(anyString(), anyMap())).thenReturn(openApi);

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
        when(httpClient.get(anyString(), anyMap())).thenReturn("");

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should return fallback endpoints");
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().contains("/api/v1/users")),
                "Fallback should include common user endpoint");
    }

    @Test
    @DisplayName("Should return fallback endpoints when HTTP calls throw exceptions")
    void testFallbackEndpointsOnException() throws IOException {
        when(httpClient.get(anyString(), anyMap())).thenThrow(new IOException("Connection refused"));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should return fallback endpoints on network error");
    }

    @Test
    @DisplayName("Should discover endpoints from reachable API roots")
    void testDiscoverFromApiRoot() throws IOException {
        // Spec paths return empty, but the /api root returns a non-empty JSON response
        when(httpClient.get(anyString(), anyMap())).thenAnswer(inv -> {
            String url = inv.getArgument(0);
            if (url.contains("swagger") || url.contains("openapi") || url.contains("api-docs")) {
                return "";
            }
            if (url.endsWith("/api")) {
                return "{\"links\":[]}";
            }
            return "";
        });

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        // /api was reachable — should at least have added it
        assertFalse(endpoints.isEmpty());
    }

    @Test
    @DisplayName("Should not throw when spec JSON is malformed")
    void testMalformedSpecJson() throws IOException {
        String malformedJson = "{invalid json content}";
        when(httpClient.get(anyString(), anyMap())).thenReturn(malformedJson);

        assertDoesNotThrow(() -> discoveryService.discoverEndpoints());
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
        when(httpClient.get(anyString(), anyMap())).thenReturn(openApi);

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        // Only GET should be extracted; "summary" and "parameters" are not HTTP methods
        long itemEndpoints = endpoints.stream()
                .filter(e -> "/items".equals(e.getPath()))
                .count();
        assertEquals(1, itemEndpoints, "Only the GET method should be extracted for /items");
    }
}
