package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
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
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
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

    @Test
    @DisplayName("No false positive when a schema-validation error message happens to mention '__schema'")
    void testIntrospectionDisabledNoFalsePositiveOnErrorMessageMentioningSchema() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        // Real-world error text from servers with introspection disabled — the literal
        // substring "__schema" appears here even though introspection is OFF, which a naive
        // body.contains("__schema") check would misread as introspection being enabled.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"errors\":[{\"message\":\"Cannot query field \\\"__schema\\\" on type \\\"Query\\\".\"}]}"));

        List<Finding> findings = testCase.testIntrospectionEnabled(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag introspection when the response is an error, even if it mentions __schema");
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

    @Test
    @DisplayName("Depth probe is built from real, always-valid schema fields, not guessed placeholder names")
    void testDeepQueryUsesRealSchemaFields() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"data\":{\"__schema\":{\"types\":[]}}}"));

        testCase.testQueryDepthAttack(endpoint, httpClient);

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(httpClient).postWithStatus(anyString(), anyMap(), anyString(), bodyCaptor.capture());

        String sentQuery = bodyCaptor.getValue();
        // __Type.ofType is part of every spec-mandated introspection schema, so nesting it
        // reaches real depth resolution instead of failing schema validation the way guessed
        // placeholder field names ("a", "b", "c", ...) would on any real GraphQL server.
        assertTrue(sentQuery.contains("ofType"), "Deep query should chain the always-valid __Type.ofType field");
        assertFalse(sentQuery.matches(".*\\{\\s*a\\s*\\{\\s*b\\s*\\{.*"),
                "Deep query should not use guessed placeholder field names like a/b/c");
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

    // ── resolver injection ────────────────────────────────────────────────────

    @Test
    @DisplayName("Extracts mutations with a String-typed argument from introspection, unwrapping NON_NULL")
    void testExtractStringArgMutations() {
        String introspection = """
                {
                  "data": {
                    "__schema": {
                      "mutationType": {
                        "fields": [
                          {
                            "name": "createPost",
                            "args": [
                              { "name": "title", "type": { "name": null, "kind": "NON_NULL",
                                  "ofType": { "name": "String", "kind": "SCALAR" } } },
                              { "name": "authorId", "type": { "name": "ID", "kind": "SCALAR" } }
                            ]
                          },
                          {
                            "name": "deletePost",
                            "args": [
                              { "name": "id", "type": { "name": "ID", "kind": "SCALAR" } }
                            ]
                          }
                        ]
                      }
                    }
                  }
                }
                """;

        List<?> results = testCase.extractStringArgMutations(introspection);

        assertEquals(1, results.size(), "Only createPost has a String-typed argument");
    }

    @Test
    @DisplayName("Flags GraphQL resolver injection when a mutation reflects an unescaped XSS payload")
    void testResolverInjectionDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String introspection = """
                {
                  "data": {
                    "__schema": {
                      "mutationType": {
                        "fields": [
                          {
                            "name": "createComment",
                            "args": [
                              { "name": "body", "type": { "name": "String", "kind": "SCALAR" } }
                            ]
                          }
                        ]
                      }
                    }
                  }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("__schema")))
                .thenReturn(ok(introspection));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("createComment")))
                .thenReturn(ok("{\"data\":{\"createComment\":\"<script>alert('xss')</script>\"}}"));

        List<Finding> findings = testCase.testResolverInjection(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect resolver injection when the payload is reflected unescaped");
        assertEquals("GraphQL Resolver Injection Vulnerability", findings.get(0).getTitle());
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Handles a Relay-style wrapped mutation result with multiple required args (DVGA createPaste shape)")
    void testResolverInjectionHandlesWrappedResultAndMultipleArgs() throws IOException {
        // Mirrors OWASP DVGA's real createPaste mutation exactly, as observed manually:
        // createPaste(burn, content, public, title) -> CreatePaste { paste: PasteObject }
        // PasteObject has scalar fields (content, title, ...) plus a nested "owner" object.
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String mutationIntrospection = """
                {
                  "data": { "__schema": { "mutationType": { "fields": [
                    { "name": "createPaste",
                      "type": { "name": "CreatePaste", "kind": "OBJECT" },
                      "args": [
                        { "name": "burn", "type": { "name": "Boolean", "kind": "SCALAR" } },
                        { "name": "content", "type": { "name": "String", "kind": "SCALAR" } },
                        { "name": "public", "type": { "name": "Boolean", "kind": "SCALAR" } },
                        { "name": "title", "type": { "name": "String", "kind": "SCALAR" } }
                      ]
                    }
                  ] } } }
                }
                """;
        String createPasteTypeFields = """
                {
                  "data": { "__type": { "fields": [
                    { "name": "paste", "type": { "name": "PasteObject", "kind": "OBJECT" } }
                  ] } }
                }
                """;
        String pasteObjectTypeFields = """
                {
                  "data": { "__type": { "fields": [
                    { "name": "title", "type": { "name": "String", "kind": "SCALAR" } },
                    { "name": "content", "type": { "name": "String", "kind": "SCALAR" } },
                    { "name": "owner", "type": { "name": "OwnerObject", "kind": "OBJECT" } }
                  ] } }
                }
                """;
        String mutationResult = """
                {"data":{"createPaste":{"paste":{"title":"test","content":"<script>alert('xss')</script>"}}}}
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("__schema")))
                .thenReturn(ok(mutationIntrospection));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("CreatePaste")))
                .thenReturn(ok(createPasteTypeFields));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("PasteObject")))
                .thenReturn(ok(pasteObjectTypeFields));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("createPaste(")))
                .thenReturn(ok(mutationResult));

        List<Finding> findings = testCase.testResolverInjection(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect the injection reflected inside the nested 'paste' object");
        assertEquals("GraphQL Resolver Injection Vulnerability", findings.get(0).getTitle());

        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(httpClient, atLeastOnce()).postWithStatus(anyString(), anyMap(), anyString(), queryCaptor.capture());
        String mutationQuery = queryCaptor.getAllValues().stream()
                .filter(q -> q.contains("createPaste("))
                .findFirst().orElseThrow();

        assertTrue(mutationQuery.contains("burn:true"), "Non-target Boolean arg should get a default value");
        assertTrue(mutationQuery.contains("title:\\\"test\\\""), "Non-target String arg should get a default value");
        assertTrue(mutationQuery.contains("paste{"), "Selection set should recurse into the nested 'paste' object");
        assertTrue(mutationQuery.contains("content"), "Selection set should include the field that echoes injected content");
    }

    @Test
    @DisplayName("No resolver injection finding when the mutation sanitizes its input")
    void testNoResolverInjectionWhenSanitized() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String introspection = """
                {
                  "data": {
                    "__schema": {
                      "mutationType": {
                        "fields": [
                          {
                            "name": "createComment",
                            "args": [
                              { "name": "body", "type": { "name": "String", "kind": "SCALAR" } }
                            ]
                          }
                        ]
                      }
                    }
                  }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("__schema")))
                .thenReturn(ok(introspection));
        // Server escapes the payload before echoing it back — no injection.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("createComment")))
                .thenReturn(ok("{\"data\":{\"createComment\":\"&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;\"}}"));

        List<Finding> findings = testCase.testResolverInjection(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag resolver injection when the payload is properly escaped");
    }

    @Test
    @DisplayName("No resolver injection test when mutation introspection is unavailable")
    void testResolverInjectionSkippedWithoutIntrospection() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"errors\":[{\"message\":\"Introspection disabled\"}]}", Map.of()));

        List<Finding> findings = testCase.testResolverInjection(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not attempt resolver injection without a schema to work from");
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
