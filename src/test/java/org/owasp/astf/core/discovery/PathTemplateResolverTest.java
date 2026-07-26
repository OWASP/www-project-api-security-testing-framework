package org.owasp.astf.core.discovery;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@DisplayName("PathTemplateResolver unit tests")
class PathTemplateResolverTest {

    @Mock
    private HttpClient httpClient;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Resolves a template placeholder to a real value discovered from the collection endpoint")
    void testResolvesTemplateToRealValue() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/books/v1/{book_title}", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(eq("https://example.com/books/v1"), eq(Map.of())))
                .thenReturn(new HttpResponse(200, "[{\"book_title\":\"bookTitle82\"}]", Map.of()));

        EndpointInfo resolved = PathTemplateResolver.resolve(endpoint, httpClient);

        assertEquals("/books/v1/bookTitle82", resolved.getPath());
        assertTrue(resolved.isResolvedFromTemplate());
        assertEquals("https://example.com", resolved.getBaseUrl());
    }

    @Test
    @DisplayName("Returns the original endpoint unchanged when there's no template placeholder")
    void testNoPlaceholderReturnsOriginal() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/42", "GET");

        EndpointInfo result = PathTemplateResolver.resolve(endpoint, httpClient);

        assertSame(endpoint, result, "Should return the exact same instance when there's nothing to resolve");
        assertFalse(result.isResolvedFromTemplate());
    }

    @Test
    @DisplayName("Returns the original endpoint unchanged when resolution fails (collection lookup 404s)")
    void testResolutionFailureLeavesEndpointUnchanged() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/books/v1/{book_title}", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(eq("https://example.com/books/v1"), eq(Map.of())))
                .thenReturn(new HttpResponse(404, "", Map.of()));

        EndpointInfo result = PathTemplateResolver.resolve(endpoint, httpClient);

        assertSame(endpoint, result, "Should return the original endpoint, never drop it, when resolution fails");
        assertFalse(result.isResolvedFromTemplate());
        assertEquals("/books/v1/{book_title}", result.getPath(), "Path should remain the unresolved template");
    }

    @Test
    @DisplayName("Is idempotent — calling resolve() on an already-resolved endpoint is a no-op")
    void testIdempotentOnAlreadyResolvedEndpoint() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/books/v1/bookTitle82", "GET");
        endpoint.setResolvedFromTemplate(true);

        EndpointInfo result = PathTemplateResolver.resolve(endpoint, httpClient);

        assertSame(endpoint, result);
    }

    @Test
    @DisplayName("Handles exceptions gracefully, returning the original endpoint")
    void testHandlesExceptionsGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/books/v1/{book_title}", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap())).thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> {
            EndpointInfo result = PathTemplateResolver.resolve(endpoint, httpClient);
            assertSame(endpoint, result);
        });
    }
}
