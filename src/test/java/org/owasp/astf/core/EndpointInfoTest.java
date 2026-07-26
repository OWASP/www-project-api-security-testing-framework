package org.owasp.astf.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("EndpointInfo unit tests")
class EndpointInfoTest {

    @Test
    @DisplayName("getFullUrl percent-encodes an unresolved path-template placeholder (regression: VAmPI hang)")
    void testGetFullUrlEncodesCurlyBraces() {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/{username}", "GET");
        endpoint.setBaseUrl("http://127.0.0.1:5002");

        String url = endpoint.getFullUrl();

        assertFalse(url.contains("{") || url.contains("}"),
                "Raw curly braces must never reach the wire — a literal '{'/'}' in an HTTP " +
                "request line caused VAmPI's dev server to hang the connection with no response");
        assertEquals("http://127.0.0.1:5002/users/v1/%7Busername%7D", url);
    }

    @Test
    @DisplayName("getFullUrl leaves an already-concrete path untouched")
    void testGetFullUrlLeavesNormalPathUnchanged() {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/name1", "GET");
        endpoint.setBaseUrl("http://127.0.0.1:5002");

        assertEquals("http://127.0.0.1:5002/users/v1/name1", endpoint.getFullUrl());
    }

    @Test
    @DisplayName("getFullUrl falls back to the path alone when no base URL is set")
    void testGetFullUrlNoBaseUrl() {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/{username}", "GET");
        assertEquals("/users/v1/%7Busername%7D", endpoint.getFullUrl());
    }

    @Test
    @DisplayName("resolvedFromTemplate defaults to false and reflects setter changes")
    void testResolvedFromTemplateFlag() {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/{username}", "GET");
        assertFalse(endpoint.isResolvedFromTemplate());

        endpoint.setResolvedFromTemplate(true);
        assertTrue(endpoint.isResolvedFromTemplate());
    }
}
