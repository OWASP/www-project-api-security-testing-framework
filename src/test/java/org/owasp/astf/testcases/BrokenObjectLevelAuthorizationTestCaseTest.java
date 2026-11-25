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
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
    @DisplayName("Cross-user PUT sends a realistic body instead of '{}' (regression: VAmPI password-change gap)")
    void testCrossUserBolaOnPutUsesRealisticBodyNotEmpty() throws IOException {
        // VAmPI's password-change endpoint resolves and is reachable, but sending an empty "{}"
        // body never exercises the actual password-change semantics the vulnerability is about.
        EndpointInfo endpoint = new EndpointInfo(
                "/users/v1/name1/password", "PUT", "application/json", null, true);
        endpoint.setResolvedFromTemplate(true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getSecondaryAuthHeaders())
                .thenReturn(Map.of("Authorization", "Bearer secondary-user-token"));
        when(httpClient.isDestructiveTestingAllowed()).thenReturn(true);
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"message\":\"password updated\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")),
                "Should still detect cross-user access on the PUT");

        org.mockito.ArgumentCaptor<String> bodyCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(httpClient, org.mockito.Mockito.atLeastOnce())
                .putWithStatus(anyString(), anyMap(), anyString(), bodyCaptor.capture());
        assertTrue(bodyCaptor.getAllValues().stream().anyMatch(body -> body.contains("password")),
                "Request body must contain a real 'password' field, not an empty '{}' — " +
                "an empty body reaches the endpoint but never exercises password-change behavior");
        assertTrue(bodyCaptor.getAllValues().stream().noneMatch(body -> body.equals("{}")),
                "Should never fall back to an empty '{}' body for a state-changing request");
    }
    private static final Map<String, String> SECONDARY = Map.of("Authorization", "Bearer secondary-user-token");

    @Test
    @DisplayName("Without --allow-destructive, a DELETE endpoint is never sent DELETE; cross-user proof uses GET")
    void testDeleteEndpointIsProbedReadOnlyByDefault() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/items/7", "DELETE", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getSecondaryAuthHeaders()).thenReturn(SECONDARY);
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"id\":7,\"owner\":\"alice\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        verify(httpClient, never()).deleteWithStatus(anyString(), anyMap());
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")
                        && f.getDescription().contains("read-only GET")),
                "The GET on the same URL proves cross-user access without deleting anything");
    }

    @Test
    @DisplayName("Without --allow-destructive, ID substitution on a DELETE endpoint sends GET to the guessed IDs, never DELETE")
    void testIdSubstitutionNeverDeletesGuessedIdsByDefault() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/items/7", "DELETE");
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of()));

        testCase.execute(endpoint, httpClient);

        verify(httpClient, never()).deleteWithStatus(anyString(), anyMap());
        verify(httpClient, atLeastOnce()).getWithStatus(eq("https://example.com/api/items/1"), anyMap());
    }

    @Test
    @DisplayName("Write endpoint with no GET handler: reports the held-back check as INFO instead of dropping it")
    void testHeldBackCheckIsReported() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/name1/password", "PUT", "application/json", null, true);
        endpoint.setResolvedFromTemplate(true);
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getSecondaryAuthHeaders()).thenReturn(SECONDARY);
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(405, "{\"error\":\"method not allowed\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        verify(httpClient, never()).putWithStatus(anyString(), anyMap(), anyString(), anyString());
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Held Back")
                        && f.getSeverity() == org.owasp.astf.core.result.Severity.INFO
                        && f.getDescription().contains("--allow-destructive")),
                "The report must say which check did not run and how to run it");
    }

    @Test
    @DisplayName("With --allow-destructive on a stateful API, the secondary DELETE is sent first and BOLA is found")
    void testStatefulDeleteFoundWhenSecondaryGoesFirst() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/items/7", "DELETE", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getSecondaryAuthHeaders()).thenReturn(SECONDARY);
        when(httpClient.isDestructiveTestingAllowed()).thenReturn(true);
        // The object can be deleted once; afterwards it is gone (404) for everyone.
        when(httpClient.deleteWithStatus(eq("https://example.com/api/items/7"), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"deleted\":7}", Map.of()))
                .thenReturn(new HttpResponse(404, "{}", Map.of()));
        when(httpClient.getWithStatus(eq("https://example.com/api/items/7"), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of()));
        when(httpClient.deleteWithStatus(org.mockito.ArgumentMatchers.argThat(u -> !u.endsWith("/7")), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(httpClient);
        order.verify(httpClient).deleteWithStatus("https://example.com/api/items/7", SECONDARY);
        Finding finding = findings.stream().filter(f -> f.getTitle().contains("Cross-User Access Confirmed"))
                .findFirst().orElseThrow(() -> new AssertionError("stateful cross-user DELETE must be reported"));
        assertTrue(finding.getResponseDetails().contains("no longer exists for its owner"));
    }

    @Test
    @DisplayName("Public object (also returned without credentials) is not reported as cross-user BOLA")
    void testPublicObjectIsNotCrossUserBola() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/articles/42", "GET");
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getSecondaryAuthHeaders()).thenReturn(SECONDARY);
        String article = "{\"id\":42,\"title\":\"Release notes\"}";
        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(new HttpResponse(200, article, Map.of()));
        when(httpClient.getWithStatusNoAuth(anyString())).thenReturn(new HttpResponse(200, article, Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Cross-User")),
                "An object anyone can read is not an object-level authorization failure");
    }

    @Test
    @DisplayName("Secondary identity receiving its own record (different object) is MEDIUM 'not confirmed', not CRITICAL")
    void testDifferentObjectIsNotConfirmed() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/profile/42", "GET");
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getSecondaryAuthHeaders()).thenReturn(SECONDARY);
        when(httpClient.getWithStatus(anyString(), eq(Map.of())))
                .thenReturn(new HttpResponse(200, "{\"id\":42,\"username\":\"alice\"}", Map.of()));
        when(httpClient.getWithStatus(anyString(), eq(SECONDARY)))
                .thenReturn(new HttpResponse(200, "{\"id\":43,\"username\":\"bob\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")));
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Not Confirmed")
                && f.getSeverity() == org.owasp.astf.core.result.Severity.MEDIUM));
    }

    @Test
    @DisplayName("Same object with viewer-specific fields (timestamps) is still confirmed")
    void testSameObjectWithVolatileFieldsIsConfirmed() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders/42", "GET");
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getSecondaryAuthHeaders()).thenReturn(SECONDARY);
        when(httpClient.getWithStatus(anyString(), eq(Map.of())))
                .thenReturn(new HttpResponse(200, "{\"orderId\":42,\"total\":10,\"servedAt\":\"10:00:01\"}", Map.of()));
        when(httpClient.getWithStatus(anyString(), eq(SECONDARY)))
                .thenReturn(new HttpResponse(200, "{\"orderId\":42,\"total\":10,\"servedAt\":\"10:00:02\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")));
    }

    @Test
    @DisplayName("PATCH endpoints are sent as PATCH with --allow-destructive, never silently as GET (regression)")
    void testPatchIsSentAsPatch() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/notes/5", "PATCH", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");
        when(httpClient.getSecondaryAuthHeaders()).thenReturn(SECONDARY);
        when(httpClient.isDestructiveTestingAllowed()).thenReturn(true);
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"id\":5}", Map.of()));
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(405, "", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        verify(httpClient).patchWithStatus(eq("https://example.com/api/notes/5"), eq(SECONDARY), anyString(), anyString());
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Cross-User Access Confirmed")));
    }

    @Test
    @DisplayName("sameObject: identical, identifier match, wrapped object, and mismatches")
    void testSameObject() {
        assertTrue(BrokenObjectLevelAuthorizationTestCase.sameObject("{\"id\":1}", "{\"id\":1}"));
        assertTrue(BrokenObjectLevelAuthorizationTestCase.sameObject(
                "{\"data\":{\"user_id\":9,\"seen\":1}}", "{\"data\":{\"user_id\":9,\"seen\":2}}"));
        assertFalse(BrokenObjectLevelAuthorizationTestCase.sameObject("{\"id\":1}", "{\"id\":2}"));
        assertFalse(BrokenObjectLevelAuthorizationTestCase.sameObject("{\"a\":1}", "{\"a\":2}"));
        assertFalse(BrokenObjectLevelAuthorizationTestCase.sameObject("", ""));
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
