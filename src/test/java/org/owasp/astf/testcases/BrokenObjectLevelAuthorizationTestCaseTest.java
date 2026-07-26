package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@DisplayName("Broken Object Level Authorization Test Case Tests")
class BrokenObjectLevelAuthorizationTestCaseTest {

    @Mock private HttpClient httpClient;
    private BrokenObjectLevelAuthorizationTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenObjectLevelAuthorizationTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-API1-2023", testCase.getId());
        assertEquals("Broken Object Level Authorization", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should not find issues when alternate ID returns 404")
    void testNoBolaWhenAltIdNotFound() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/123", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{\"error\":\"not found\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Should detect BOLA when alternate numeric ID returns 200")
    void testBolaWithNumericId() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/42", "GET");
        endpoint.setBaseUrl("https://example.com");

        // Both original and alternate IDs return 200
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"id\":1,\"name\":\"User\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertFalse(findings.isEmpty(), "Should detect BOLA");
        assertTrue(findings.get(0).getTitle().contains("Broken Object Level Authorization"));
    }

    @Test
    @DisplayName("Should return empty for paths without resource IDs")
    void testNoIdsInPath() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "No IDs in path means no BOLA test possible");
    }

    @Test
    @DisplayName("Should detect BOLA with UUID substitution")
    void testBolaWithUuid() throws IOException {
        EndpointInfo endpoint = new EndpointInfo(
                "/api/orders/550e8400-e29b-41d4-a716-446655440000", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"orderId\":\"any\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertFalse(findings.isEmpty(), "Should detect UUID-based BOLA");
    }

    @Test
    @DisplayName("Should detect real cross-user BOLA when a secondary identity accesses the same object (regression, #87)")
    void testCrossUserBolaDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders/42", "GET");
        endpoint.setBaseUrl("https://example.com");

        // A secondary identity is configured — HttpClient reports its override headers.
        when(httpClient.getSecondaryAuthHeaders())
                .thenReturn(Map.of("Authorization", "Bearer secondary-user-token"));
        // Both the primary (Map.of() headers) and secondary (override headers) requests to the
        // exact same object ID succeed — no ID substitution involved at all.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"orderId\":42,\"owner\":\"someone-else\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")),
                "Should detect BOLA when a second identity accesses the same object without ID substitution");
    }

    @Test
    @DisplayName("Should NOT run cross-user BOLA check when no secondary identity is configured")
    void testNoCrossUserBolaWithoutSecondaryIdentity() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders/42", "GET");
        endpoint.setBaseUrl("https://example.com");

        // getSecondaryAuthHeaders() defaults to an empty map (Mockito's default for
        // unstubbed Map-returning methods) — simulating no --secondary-token configured.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")),
                "Should not attempt cross-user BOLA testing when no secondary identity is configured");
    }

    @Test
    @DisplayName("Should NOT flag cross-user BOLA when the secondary identity is rejected")
    void testNoCrossUserBolaWhenSecondaryRejected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders/42", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getSecondaryAuthHeaders())
                .thenReturn(Map.of("Authorization", "Bearer secondary-user-token"));
        // Primary succeeds; secondary is correctly rejected with 403 — proper authorization.
        when(httpClient.getWithStatus(argThat(url -> true), eq(Map.of())))
                .thenReturn(new HttpResponse(200, "{\"orderId\":42}", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> true), eq(Map.of("Authorization", "Bearer secondary-user-token"))))
                .thenReturn(new HttpResponse(403, "{\"error\":\"forbidden\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")),
                "Should not flag cross-user BOLA when the secondary identity is correctly rejected");
    }

    @Test
    @DisplayName("Resolves an unresolved path template (e.g. VAmPI's {book_title}) to a real value and detects BOLA (regression, #95)")
    void testResolvesTemplatePlaceholderAndDetectsCrossUserBola() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/books/v1/{book_title}", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getSecondaryAuthHeaders())
                .thenReturn(Map.of("Authorization", "Bearer secondary-user-token"));

        // The collection endpoint (placeholder segment + everything after it stripped) returns
        // a list of real books — "bookTitle82" is the plausible identifier to resolve to.
        when(httpClient.getWithStatus(eq("https://example.com/books/v1"), eq(Map.of())))
                .thenReturn(new HttpResponse(200,
                        "[{\"book_title\":\"bookTitle82\",\"secret_content\":\"top secret\"}]", Map.of()));

        // Both identities can read the resolved, real object with no ID substitution.
        when(httpClient.getWithStatus(eq("https://example.com/books/v1/bookTitle82"), eq(Map.of())))
                .thenReturn(new HttpResponse(200, "{\"secret_content\":\"top secret\"}", Map.of()));
        when(httpClient.getWithStatus(eq("https://example.com/books/v1/bookTitle82"),
                eq(Map.of("Authorization", "Bearer secondary-user-token"))))
                .thenReturn(new HttpResponse(200, "{\"secret_content\":\"top secret\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")),
                "Should resolve {book_title} to a real value and detect the cross-user BOLA on it");
    }

    @Test
    @DisplayName("Falls back to the original (unresolved) endpoint when the collection lookup fails")
    void testTemplatePlaceholderResolutionFailsGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/books/v1/{book_title}", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getSecondaryAuthHeaders())
                .thenReturn(Map.of("Authorization", "Bearer secondary-user-token"));
        // Collection lookup fails (404) — nothing to resolve to.
        when(httpClient.getWithStatus(eq("https://example.com/books/v1"), eq(Map.of())))
                .thenReturn(new HttpResponse(404, "", Map.of()));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")),
                "Should not attempt BOLA testing on a still-unresolved placeholder path");
    }

    @Test
    @DisplayName("Handles exceptions gracefully")
    void testExceptionHandling() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection failed"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }
}
