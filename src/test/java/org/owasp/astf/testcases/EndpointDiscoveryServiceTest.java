package org.owasp.astf.testcases;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.discovery.EndpointDiscoveryService;
import org.owasp.astf.core.http.HttpClient;

class EndpointDiscoveryServiceTest {

    @Mock
    private ScanConfig mockConfig;

    @Mock
    private HttpClient mockHttpClient;

    private EndpointDiscoveryService discoveryService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getTargetUrl()).thenReturn("http://example.com");
        discoveryService = new EndpointDiscoveryService(mockConfig, mockHttpClient);
    }

    @Test
    @DisplayName("Should discover endpoints from OpenAPI specifications")
    void testDiscoverFromSpecifications() throws IOException {
        String mockSpecResponse = """
            {
                "openapi": "3.0.0",
                "paths": {
                    "/users": {
                        "get": {},
                        "post": {}
                    },
                    "/products": {
                        "get": {}
                    }
                }
            }
        """;

        when(mockHttpClient.get(anyString(), anyMap())).thenReturn(mockSpecResponse);

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertEquals(3, endpoints.size(), "Should discover 3 endpoints");
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().equals("/users") && e.getMethod().equals("GET")));
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().equals("/users") && e.getMethod().equals("POST")));
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().equals("/products") && e.getMethod().equals("GET")));
    }

    @Test
    @DisplayName("Should fallback to common endpoints when discovery fails")
    void testFallbackEndpoints() throws IOException {
        when(mockHttpClient.get(anyString(), anyMap())).thenThrow(new IOException("Mocked exception"));

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Fallback endpoints should be used");
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().equals("/api/v1/users") && e.getMethod().equals("GET")));
    }

    @Test
    @DisplayName("Should explore common API root paths")
    void testExploreApiRoots() throws IOException {
        when(mockHttpClient.get(eq("http://example.com/api"), anyMap())).thenReturn("{\"data\":\"success\"}");

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should discover endpoints from common API roots");
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().equals("/api") && e.getMethod().equals("GET")));
    }

    @Test
    @DisplayName("Should test common resource patterns")
    void testCommonResourcePatterns() throws IOException {
        when(mockHttpClient.get(eq("http://example.com/api/users"), anyMap())).thenReturn("{\"data\":\"success\"}");

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should discover endpoints from common resource patterns");
        assertTrue(endpoints.stream().anyMatch(e -> e.getPath().equals("/api/users") && e.getMethod().equals("GET")));
    }

    @Test
    @DisplayName("Should handle invalid JSON responses gracefully")
    void testInvalidJsonResponse() throws IOException {
        when(mockHttpClient.get(anyString(), anyMap())).thenReturn("Invalid JSON");

        List<EndpointInfo> endpoints = discoveryService.discoverEndpoints();

        assertFalse(endpoints.isEmpty(), "Should fallback to common endpoints on invalid JSON");
    }
}
