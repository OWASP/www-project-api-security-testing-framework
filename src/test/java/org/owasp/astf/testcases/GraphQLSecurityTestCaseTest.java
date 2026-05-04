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
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link GraphQLSecurityTestCase}.
 *
 * <p>Covers introspection detection, field suggestion leakage, query depth enforcement,
 * batch query abuse, endpoint discovery, and non-GraphQL endpoint skipping.</p>
 */
@DisplayName("GraphQLSecurityTestCase unit tests")
class GraphQLSecurityTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private GraphQLSecurityTestCase testCase;

    // ── helpers ───────────────────────────────────────────────────────────────

    private static HttpResponse ok(String body) {
        return new HttpResponse(200, body, Map.of());
    }

    private static HttpResponse notFound() {
        return new HttpResponse(404, "{}", Map.of());
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new GraphQLSecurityTestCase();
    }

    // ── metadata ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getId / getName / getDescription return expected values")
    void testMetadata() {
        assertEquals("ASTF-GRAPHQL-2023", testCase.getId());
        assertEquals("GraphQL Security", testCase.getName());
        assertNotNull(testCase.getDescription());
        assertFalse(testCase.getDescription().isBlank());
    }

    // ── introspection ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("Flags introspection when response contains __schema")
    void testIntrospectionEnabled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}"));

        List<Finding> findings = testCase.testIntrospectionEnabled(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect introspection enabled");
        Finding f = findings.get(0);
        assertEquals("GraphQL Introspection Enabled in Production", f.getTitle());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertTrue(f.getEvidence().contains("__schema"));
    }

    @Test
    @DisplayName("No finding when introspection is disabled (no __schema in response)")
    void testIntrospectionDisabled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"errors\":[{\"message\":\"Introspection disabled\"}]}"));

        List<Finding> findings = testCase.testIntrospectionEnabled(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "No finding when introspection is disabled");
    }

    // ── field suggestion leakage ──────────────────────────────────────────────

    @Test
    @DisplayName("Flags field suggestion leakage when response contains 'Did you mean'")
    void testFieldSuggestionLeakage() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"errors\":[{\"message\":\"Cannot query field '__typenme'. Did you mean '__typename'?\"}]}"));

        List<Finding> findings = testCase.testFieldSuggestionLeakage(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect field suggestion leakage");
        Finding f = findings.get(0);
        assertEquals("GraphQL Field Suggestion Leakage", f.getTitle());
        assertEquals(Severity.LOW, f.getSeverity());
    }

    @Test
    @DisplayName("No field suggestion finding when server gives generic error")
    void testNoFieldSuggestionWhenSuppressed() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"errors\":[{\"message\":\"Unknown field.\"}]}"));

        List<Finding> findings = testCase.testFieldSuggestionLeakage(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "No finding when suggestion is suppressed");
    }

    // ── query depth ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("Flags missing depth limit when server accepts deep query")
    void testQueryDepthNotEnforced() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"data\":{\"a\":{\"b\":{\"c\":{}}}}}"));

        List<Finding> findings = testCase.testQueryDepthAttack(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should flag missing depth limit");
        assertEquals("GraphQL Query Depth Limit Not Enforced", findings.get(0).getTitle());
        assertEquals(Severity.MEDIUM, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("No depth finding when server rejects deep query")
    void testQueryDepthEnforced() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400,
                        "{\"errors\":[{\"message\":\"Query depth limit exceeded\"}]}",
                        Map.of()));

        List<Finding> findings = testCase.testQueryDepthAttack(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "No finding when depth limit is enforced");
    }

    // ── batch query ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("Flags batch query abuse when server returns array response")
    void testBatchQueryAbuse() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("[{\"data\":{\"__typename\":\"Query\"}},{\"data\":{\"__typename\":\"Query\"}}]"));

        List<Finding> findings = testCase.testBatchQueryAbuse(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect batch query support");
        assertEquals("GraphQL Batch Query Abuse Possible", findings.get(0).getTitle());
        assertEquals(Severity.LOW, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("No batch finding when server rejects batched requests")
    void testBatchQueryRejected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400,
                        "{\"errors\":[{\"message\":\"Batch queries not supported\"}]}",
                        Map.of()));

        List<Finding> findings = testCase.testBatchQueryAbuse(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "No finding when batching is rejected");
    }

    // ── endpoint detection ────────────────────────────────────────────────────

    @Test
    @DisplayName("isGraphQLEndpoint returns true for paths containing 'graphql'")
    void testIsGraphQLEndpoint() {
        assertTrue(testCase.isGraphQLEndpoint(new EndpointInfo("/graphql", "POST")));
        assertTrue(testCase.isGraphQLEndpoint(new EndpointInfo("/api/graphql", "POST")));
        assertTrue(testCase.isGraphQLEndpoint(new EndpointInfo("/gql", "POST")));
        assertFalse(testCase.isGraphQLEndpoint(new EndpointInfo("/api/users", "GET")));
    }

    @Test
    @DisplayName("execute skips non-GraphQL endpoints when no GraphQL path is discovered")
    void testNonGraphQLEndpointSkipped() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        // All discovery probes return 404
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(notFound());

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Non-GraphQL endpoints should produce no findings");
    }

    @Test
    @DisplayName("execute handles IOException without propagating it")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }
}
