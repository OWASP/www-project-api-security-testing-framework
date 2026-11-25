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

@DisplayName("Broken Function Level Authorization Test Case Tests")
class BrokenFunctionLevelAuthorizationTestCaseTest {

    @Mock private HttpClient httpClient;
    private BrokenFunctionLevelAuthorizationTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenFunctionLevelAuthorizationTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-API5-2023", testCase.getId());
        assertEquals("Broken Function Level Authorization", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should detect accessible admin endpoint")
    void testAdminEndpointAccessible() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.contains("/admin")) {
                        return new HttpResponse(200, "{\"users\":[], \"admin\":true}", Map.of());
                    }
                    return new HttpResponse(200, "{\"users\":[]}", Map.of());
                });
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                f.getTitle().contains("Administrative") || f.getTitle().contains("Endpoint")),
                "Should detect accessible admin endpoint");
    }

    @Test
    @DisplayName("Should detect HTTP method escalation")
    void testHttpMethodEscalation() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // GET works, DELETE also works (vulnerability)
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of())); // Admin not found
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"updated\":true}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));

        // For the GET endpoint itself (used in method escalation test)
        when(httpClient.getWithStatus(eq("https://example.com/api/users"), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"users\":[]}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                f.getTitle().contains("Method") || f.getTitle().contains("Authorization")),
                "Should detect HTTP method escalation");
    }

    @Test
    @DisplayName("Should NOT flag method escalation when responses are an SPA/reverse-proxy HTML fallback (regression)")
    void testNoMethodEscalationOnHtmlFallback() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // A single-page app / catch-all reverse proxy returns 200 text/html for every method,
        // including PUT/DELETE/PATCH — this must not be read as "method escalation allowed".
        HttpResponse htmlFallback = new HttpResponse(200, "<html><body>App</body></html>",
                Map.of("Content-Type", List.of("text/html")));

        when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(htmlFallback);
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString())).thenReturn(htmlFallback);
        when(httpClient.deleteWithStatus(anyString(), anyMap())).thenReturn(htmlFallback);
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString())).thenReturn(htmlFallback);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Method")),
                "Should not flag HTTP method escalation when the response is an HTML SPA fallback page");
    }

    @Test
    @DisplayName("Should return empty when admin endpoints return 401/403")
    void testAdminEndpointReturns401() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        // All requests properly require authentication
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not find issues when auth is enforced");
    }

    @Test
    @DisplayName("Detects BFLA via privilege-tier path substitution (regression: crAPI's /user/videos vs /admin/videos)")
    void testPrivilegeTierPathSubstitutionDetected() throws IOException {
        // crAPI's real vulnerability: DELETE /identity/api/v2/user/videos/{id} always denies,
        // but the sibling DELETE /identity/api/v2/admin/videos/{id} succeeds with the same,
        // non-admin token — confirmed by reading crAPI's actual ProfileController.java source.
        EndpointInfo endpoint = new EndpointInfo("/identity/api/v2/user/videos/42", "DELETE");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.deleteWithStatus(eq("https://example.com/identity/api/v2/user/videos/42"), anyMap()))
                .thenReturn(new HttpResponse(403, "{\"error\":\"forbidden\"}", Map.of()));
        when(httpClient.deleteWithStatus(eq("https://example.com/identity/api/v2/admin/videos/42"), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"message\":\"video deleted\"}", Map.of()));

        List<Finding> findings = testCase.testPrivilegeTierPathSubstitution(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect privilege-tier path substitution BFLA");
        assertEquals("Broken Function Level Authorization (Privilege-Tier Path Substitution)",
                findings.get(0).getTitle());
    }

    @Test
    @DisplayName("Does not flag privilege-tier substitution when the original request already succeeds")
    void testPrivilegeTierPathSubstitutionNotFlaggedWhenOriginalSucceeds() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/identity/api/v2/user/videos/42", "DELETE");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"message\":\"ok\"}", Map.of()));

        List<Finding> findings = testCase.testPrivilegeTierPathSubstitution(endpoint, httpClient);

        assertTrue(findings.isEmpty(),
                "Should not flag substitution when the original (non-substituted) request already succeeds");
    }

    @Test
    @DisplayName("Does not attempt privilege-tier substitution when no low-privilege segment is present")
    void testPrivilegeTierPathSubstitutionSkippedWithoutMatchingSegment() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders/42", "DELETE");
        endpoint.setBaseUrl("https://example.com");

        List<Finding> findings = testCase.testPrivilegeTierPathSubstitution(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not attempt substitution without a matching path segment");
    }

    @Test
    @DisplayName("Should NOT report admin endpoints when a gateway answers 200 JSON for every unknown path (regression)")
    void testNoAdminFindingsOnJsonCatchAll() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders", "GET");
        endpoint.setBaseUrl("https://example.com");

        // An API gateway default route answering 200 with a JSON envelope. The existing
        // content-type guard only screens out HTML catch-alls, so without an unknown-path
        // baseline all 21 probed admin paths would be reported as CRITICAL.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"success\":false,\"data\":null}",
                        Map.of("Content-Type", List.of("application/json"))));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Administrative")),
                "A JSON catch-all must not be reported as 21 accessible administrative endpoints");
    }

    @Test
    @DisplayName("Should still report a real admin endpoint on a catch-all target (no false negative)")
    void testRealAdminEndpointStillDetectedOnCatchAllTarget() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/orders", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    if (url.endsWith("/admin")) {
                        return new HttpResponse(200,
                                "{\"users\":[{\"id\":1,\"role\":\"admin\"}],\"canImpersonate\":true}",
                                Map.of("Content-Type", List.of("application/json")));
                    }
                    return new HttpResponse(200, "{\"success\":false,\"data\":null}",
                            Map.of("Content-Type", List.of("application/json")));
                });
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.deleteWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));
        when(httpClient.patchWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(405, "{}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Administrative")),
                "A real admin payload differs from the catch-all envelope and must still be reported");
    }

    @Test
    @DisplayName("Should handle exceptions gracefully")
    void testExceptionHandling() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
    }

    private static final Map<String, List<String>> JSON_HEADERS = Map.of("Content-Type", List.of("application/json"));
    private static final String ROLE_MATRIX_TITLE_PREFIX = "Function-Level Authorization";

    private EndpointInfo roleMatrixEndpoint() {
        EndpointInfo endpoint = new EndpointInfo("/api/admin/users", "GET");
        endpoint.setBaseUrl("https://example.com");
        return endpoint;
    }

    private void stubRoleMatrix(HttpResponse admin, HttpResponse user, HttpResponse anon) throws IOException {
        when(httpClient.getConfiguredAdminToken()).thenReturn("admin-secret");
        when(httpClient.getAdminAuthHeaders()).thenReturn(Map.of("Authorization", "Bearer admin-secret"));
        when(httpClient.getWithStatus(anyString(), anyMap())).thenAnswer(inv -> {
            Map<String, String> headers = inv.getArgument(1);
            return headers.containsKey("Authorization") ? admin : user;
        });
        when(httpClient.getWithStatusNoAuth(anyString())).thenReturn(anon);
    }

    private List<Finding> roleMatrixFindings(List<Finding> findings) {
        return findings.stream().filter(f -> f.getTitle().startsWith(ROLE_MATRIX_TITLE_PREFIX)).toList();
    }

    @Test
    @DisplayName("Role matrix: admin 200 and user 200 with the same body is CRITICAL")
    void testRoleMatrixSameBodyCritical() throws IOException {
        String body = "{\"users\":[{\"id\":1},{\"id\":2}]}";
        stubRoleMatrix(new HttpResponse(200, body, JSON_HEADERS),
                new HttpResponse(200, "{ \"users\": [ {\"id\":1}, {\"id\":2} ] }", JSON_HEADERS),
                new HttpResponse(401, "{}", JSON_HEADERS));

        List<Finding> findings = roleMatrixFindings(testCase.execute(roleMatrixEndpoint(), httpClient));

        assertEquals(1, findings.size());
        assertEquals("Function-Level Authorization Missing", findings.get(0).getTitle());
        assertEquals(org.owasp.astf.core.result.Severity.CRITICAL, findings.get(0).getSeverity());
        assertFalse(String.valueOf(findings.get(0).getResponseDetails()).contains("admin-secret"));
        assertFalse(String.valueOf(findings.get(0).getRequestDetails()).contains("admin-secret"));
    }

    @Test
    @DisplayName("Role matrix: admin 200 and user 403 produces no finding")
    void testRoleMatrixUserForbidden() throws IOException {
        stubRoleMatrix(new HttpResponse(200, "{\"users\":[1,2]}", JSON_HEADERS),
                new HttpResponse(403, "{\"error\":\"forbidden\"}", JSON_HEADERS),
                new HttpResponse(401, "{}", JSON_HEADERS));

        List<Finding> findings = roleMatrixFindings(testCase.execute(roleMatrixEndpoint(), httpClient));

        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Role matrix: admin 200 and user 200 with a different body is MEDIUM Not Confirmed")
    void testRoleMatrixDifferentBodyMedium() throws IOException {
        stubRoleMatrix(new HttpResponse(200, "{\"users\":[1,2,3],\"audit\":true}", JSON_HEADERS),
                new HttpResponse(200, "{\"users\":[1]}", JSON_HEADERS),
                new HttpResponse(401, "{}", JSON_HEADERS));

        List<Finding> findings = roleMatrixFindings(testCase.execute(roleMatrixEndpoint(), httpClient));

        assertEquals(1, findings.size());
        assertEquals("Function-Level Authorization Not Confirmed", findings.get(0).getTitle());
        assertEquals(org.owasp.astf.core.result.Severity.MEDIUM, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Role matrix: skipped silently when no admin token is configured")
    void testRoleMatrixSkippedWithoutAdminToken() throws IOException {
        when(httpClient.getConfiguredAdminToken()).thenReturn(null);

        List<Finding> findings = testCase.testRoleMatrix(roleMatrixEndpoint(), httpClient);

        assertTrue(findings.isEmpty());
        org.mockito.Mockito.verify(httpClient, org.mockito.Mockito.never()).getWithStatus(anyString(), anyMap());
        org.mockito.Mockito.verify(httpClient, org.mockito.Mockito.never()).getWithStatusNoAuth(anyString());
    }

    @Test
    @DisplayName("Role matrix: write methods are not replayed")
    void testRoleMatrixIgnoresWrites() throws IOException {
        when(httpClient.getConfiguredAdminToken()).thenReturn("admin-secret");
        EndpointInfo endpoint = new EndpointInfo("/api/admin/users", "DELETE");
        endpoint.setBaseUrl("https://example.com");

        assertTrue(testCase.testRoleMatrix(endpoint, httpClient).isEmpty());
        org.mockito.Mockito.verify(httpClient, org.mockito.Mockito.never()).getWithStatus(anyString(), anyMap());
    }
}
