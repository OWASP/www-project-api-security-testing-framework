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

    // ── field duplication / alias / circular fragment DoS (#101) ──────────────

    @Test
    @DisplayName("Detects field duplication DoS when the repeated-selection request times out")
    void testFieldDuplicationDetectedViaTimeout() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        // Distinguish the short single-copy baseline from the ~60x-repeated probe by length
        // rather than fragile brace-counting substring matching.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), argThat(q -> q != null && q.length() < 200)))
                .thenReturn(ok("{\"data\":{\"__schema\":{\"types\":[]}}}"));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), argThat(q -> q != null && q.length() >= 200)))
                .thenThrow(new IOException("Read timed out"));

        List<Finding> findings = testCase.testFieldDuplicationAttack(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect field duplication DoS from the timeout");
        assertEquals("GraphQL Field Duplication Denial of Service", findings.get(0).getTitle());
        assertEquals(Severity.MEDIUM, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Does not flag field duplication when both requests are fast")
    void testFieldDuplicationNotDetectedWhenFast() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"data\":{\"__schema\":{\"types\":[]}}}"));

        List<Finding> findings = testCase.testFieldDuplicationAttack(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects alias-based DoS when the aliased-repetition request times out")
    void testAliasBasedAttackDetectedViaTimeout() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(q -> q != null && q.contains("a59:"))))
                .thenThrow(new IOException("Read timed out"));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(q -> q != null && !q.contains("a59:"))))
                .thenReturn(ok("{\"data\":{\"a0\":{\"types\":[]}}}"));

        List<Finding> findings = testCase.testAliasBasedAttack(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect alias-based DoS from the timeout");
        assertEquals("GraphQL Alias-Based Denial of Service", findings.get(0).getTitle());
    }

    @Test
    @DisplayName("Does not flag alias-based attack when both requests are fast")
    void testAliasBasedAttackNotDetectedWhenFast() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"data\":{\"a0\":{\"types\":[]}}}"));

        List<Finding> findings = testCase.testAliasBasedAttack(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects circular fragment DoS when the request times out")
    void testCircularFragmentDetectedViaTimeout() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Read timed out"));

        List<Finding> findings = testCase.testCircularFragmentAttack(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect circular fragment DoS from the timeout");
        assertEquals("GraphQL Circular Fragment Denial of Service", findings.get(0).getTitle());
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Does not flag circular fragment when the server rejects it quickly")
    void testCircularFragmentNotDetectedWhenRejectedFast() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400,
                        "{\"errors\":[{\"message\":\"Cannot spread fragment 'A' within itself\"}]}", Map.of()));

        List<Finding> findings = testCase.testCircularFragmentAttack(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "A fast validation rejection is the correct, safe behavior");
    }

    // ── GraphQL IDE exposure (#102) ────────────────────────────────────────────

    @Test
    @DisplayName("Detects an exposed GraphiQL interface")
    void testGraphiQLExposureDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(argThat(url -> url != null && url.endsWith("/graphiql")), anyMap()))
                .thenReturn(new HttpResponse(200, "<html><title>GraphiQL</title></html>", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.endsWith("/graphiql")), anyMap()))
                .thenReturn(new HttpResponse(404, "", Map.of()));

        List<Finding> findings = testCase.testGraphiQLExposure(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().equals("GraphQL IDE Exposed in Production")));
    }

    @Test
    @DisplayName("Detects a GraphiQL interface gated behind a guessable debug cookie")
    void testGraphiQLCookieBypassDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(argThat(url -> url != null && url.endsWith("/graphiql")), eq(Map.of())))
                .thenReturn(new HttpResponse(403, "Forbidden", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && url.endsWith("/graphiql")),
                argThat(h -> h != null && h.containsKey("Cookie"))))
                .thenReturn(new HttpResponse(200, "<html><title>GraphiQL</title></html>", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.endsWith("/graphiql")), anyMap()))
                .thenReturn(new HttpResponse(404, "", Map.of()));

        List<Finding> findings = testCase.testGraphiQLExposure(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Guessable Cookie")));
    }

    @Test
    @DisplayName("Does not flag GraphiQL exposure when every IDE path is blocked")
    void testGraphiQLExposureNotDetectedWhenBlocked() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "", Map.of()));

        List<Finding> findings = testCase.testGraphiQLExposure(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    // ── deny-list bypass via fragment wrapping (#102) ─────────────────────────

    @Test
    @DisplayName("Detects deny-list bypass when a blocked field succeeds via fragment wrapping")
    void testDenyListBypassDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String queryIntrospection = """
                {
                  "data": { "__schema": { "queryType": { "fields": [
                    { "name": "adminUsers", "args": [] }
                  ] } } }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("queryType")))
                .thenReturn(ok(queryIntrospection));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(q -> q != null && q.contains("{adminUsers{__typename}}"))))
                .thenReturn(new HttpResponse(200, "{\"errors\":[{\"message\":\"Operation not allowed\"}]}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(q -> q != null && q.contains("fragment F"))))
                .thenReturn(ok("{\"data\":{\"adminUsers\":{\"__typename\":\"AdminUsers\"}}}"));

        List<Finding> findings = testCase.testOperationDenyListBypass(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect the fragment-wrapping bypass");
        assertEquals("GraphQL Deny-List Bypass via Fragment Wrapping", findings.get(0).getTitle());
    }

    @Test
    @DisplayName("Does not flag deny-list bypass when the direct call already succeeds")
    void testDenyListBypassNotDetectedWhenNotBlocked() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String queryIntrospection = """
                {
                  "data": { "__schema": { "queryType": { "fields": [
                    { "name": "adminUsers", "args": [] }
                  ] } } }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("queryType")))
                .thenReturn(ok(queryIntrospection));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("adminUsers")))
                .thenReturn(ok("{\"data\":{\"adminUsers\":{\"__typename\":\"AdminUsers\"}}}"));

        List<Finding> findings = testCase.testOperationDenyListBypass(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "Nothing to bypass when the field isn't blocked in the first place");
    }

    @Test
    @DisplayName("Does not flag deny-list bypass when no sensitive-sounding field exists")
    void testDenyListBypassSkippedWithoutSensitiveField() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String queryIntrospection = """
                {
                  "data": { "__schema": { "queryType": { "fields": [
                    { "name": "products", "args": [] }
                  ] } } }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok(queryIntrospection));

        List<Finding> findings = testCase.testOperationDenyListBypass(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    // ── argument-based auth bypass (#102) ──────────────────────────────────────

    @Test
    @DisplayName("Detects argument-based auth bypass when a none-alg JWT query argument is accepted")
    void testArgumentBasedAuthBypassDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), eq("{\"query\":\"{__typename}\"}")))
                .thenReturn(ok("{\"data\":{\"__typename\":\"Query\"}}"));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("me(token:")))
                .thenReturn(ok("{\"data\":{\"me\":{\"__typename\":\"User\"}}}"));

        List<Finding> findings = testCase.testArgumentBasedAuthBypass(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect the argument-based auth bypass");
        assertEquals("GraphQL Argument-Based Authentication Bypass", findings.get(0).getTitle());
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Does not flag argument-based auth bypass when every candidate field rejects the forged token")
    void testArgumentBasedAuthBypassNotDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), eq("{\"query\":\"{__typename}\"}")))
                .thenReturn(ok("{\"data\":{\"__typename\":\"Query\"}}"));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("token:")))
                .thenReturn(new HttpResponse(200, "{\"errors\":[{\"message\":\"Unauthorized\"}]}", Map.of()));

        List<Finding> findings = testCase.testArgumentBasedAuthBypass(endpoint, httpClient);
        assertTrue(findings.isEmpty());
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

        List<?> results = testCase.extractStringArgFields(introspection, "mutationType");

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
    @DisplayName("Detects injection in a SECOND vulnerable mutation instead of stopping after the first (regression, #100)")
    void testResolverInjectionFindsMultipleVulnerableMutations() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String introspection = """
                {
                  "data": { "__schema": { "mutationType": { "fields": [
                    { "name": "createComment", "args": [
                        { "name": "body", "type": { "name": "String", "kind": "SCALAR" } } ] },
                    { "name": "updateBio", "args": [
                        { "name": "bio", "type": { "name": "String", "kind": "SCALAR" } } ] }
                  ] } } }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("mutationType")))
                .thenReturn(ok(introspection));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("queryType")))
                .thenReturn(new HttpResponse(200, "{\"errors\":[{\"message\":\"no query fields\"}]}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("createComment")))
                .thenReturn(ok("{\"data\":{\"createComment\":\"<script>alert('xss')</script>\"}}"));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("updateBio")))
                .thenReturn(ok("{\"data\":{\"updateBio\":\"<script>alert('xss')</script>\"}}"));

        List<Finding> findings = testCase.testResolverInjection(endpoint, httpClient);

        assertEquals(2, findings.size(), "Both vulnerable mutations should be reported, not just the first");
    }

    @Test
    @DisplayName("Detects injection in a QUERY field, not just mutations (regression, #100)")
    void testResolverInjectionCoversQueryFields() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String noMutations = """
                { "data": { "__schema": { "mutationType": { "fields": [] } } } }
                """;
        String queryIntrospection = """
                {
                  "data": { "__schema": { "queryType": { "fields": [
                    { "name": "pastes", "args": [
                        { "name": "filter", "type": { "name": "String", "kind": "SCALAR" } } ] }
                  ] } } }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("mutationType")))
                .thenReturn(ok(noMutations));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("queryType")))
                .thenReturn(ok(queryIntrospection));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("pastes")))
                .thenReturn(ok("{\"data\":{\"pastes\":\"sql syntax error near ''\"}}"));

        List<Finding> findings = testCase.testResolverInjection(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect injection in a query field");
        assertEquals("GraphQL Resolver Injection Vulnerability", findings.get(0).getTitle());
        assertTrue(findings.get(0).getRequestDetails().contains("query"),
                "Evidence should reflect this was found via a query field, not a mutation");
    }

    @Test
    @DisplayName("Detects GraphQL resolver SSRF when a URL-shaped argument reflects cloud metadata (regression, #100)")
    void testResolverInjectionDetectsSsrf() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/graphql", "POST");
        String introspection = """
                {
                  "data": { "__schema": { "mutationType": { "fields": [
                    { "name": "importImage", "args": [
                        { "name": "url", "type": { "name": "String", "kind": "SCALAR" } } ] }
                  ] } } }
                }
                """;

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("mutationType")))
                .thenReturn(ok(introspection));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("queryType")))
                .thenReturn(new HttpResponse(200, "{\"errors\":[{\"message\":\"no query fields\"}]}", Map.of()));
        // Benign/XSS-style payloads are rejected or unreflected; only the SSRF metadata URL succeeds.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), contains("importImage")))
                .thenReturn(ok("{\"data\":{\"importImage\":\"upload failed\"}}"));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                contains("169.254.169.254")))
                .thenReturn(ok("{\"data\":{\"importImage\":\"ami-id: ami-0abcdef1234567890\"}}"));

        List<Finding> findings = testCase.testResolverInjection(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect SSRF via the URL-shaped argument");
        assertEquals("GraphQL Resolver SSRF Vulnerability", findings.get(0).getTitle());
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
