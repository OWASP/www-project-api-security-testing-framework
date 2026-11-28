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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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

        // The target answers the same without credentials as with them.
        OpenTargetStubs.answerNoAuthLikeCredentialed(httpClient);

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

        // The target answers the same without credentials as with them.
        OpenTargetStubs.answerNoAuthLikeCredentialed(httpClient);

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

        // The target answers the same without credentials as with them.
        OpenTargetStubs.answerNoAuthLikeCredentialed(httpClient);

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

    private static final String BASE = "https://example.com";

    /**
     * Anonymous target: '/admin' answers 403, the given bypass URL answers 200 with admin JSON,
     * '/' answers 200 with a small status body, everything else 404.
     */
    private void protectedAdminWithBypass(String bypassUrl) throws IOException {
        when(httpClient.getWithStatusNoAuth(anyString())).thenAnswer(inv -> {
            String url = inv.getArgument(0);
            if (url.equals(BASE + "/admin")) {
                return new HttpResponse(403, "{\"error\":\"forbidden\"}", Map.of());
            }
            if (url.equals(bypassUrl)) {
                return new HttpResponse(200, "{\"users\":[{\"id\":1,\"role\":\"admin\"}]}", Map.of());
            }
            if (url.equals(BASE + "/")) {
                return new HttpResponse(200, "{\"status\":\"ok\"}", Map.of());
            }
            return new HttpResponse(404, "{\"error\":\"not found\"}", Map.of());
        });
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of()));
    }

    private static EndpointInfo usersEndpoint() {
        EndpointInfo endpoint = new EndpointInfo("/api/items", "POST");
        endpoint.setBaseUrl(BASE);
        return endpoint;
    }

    private static List<Finding> bypassFindings(List<Finding> findings) {
        return findings.stream()
                .filter(f -> f.getTitle().equals("Administrative Endpoint Access Control Bypass"))
                .toList();
    }

    @Test
    @DisplayName("Protected admin path served under ';/' without credentials is a CRITICAL bypass")
    void testSemicolonPathBypass() throws IOException {
        protectedAdminWithBypass(BASE + "/admin;/");

        List<Finding> findings = bypassFindings(testCase.execute(usersEndpoint(), httpClient));

        assertEquals(1, findings.size());
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getRequestDetails().contains("/admin;/"));
        assertTrue(findings.get(0).getDescription().contains("HTTP 403"));
    }

    @Test
    @DisplayName("X-Original-URL that returns a different body from '/' is a bypass")
    void testRewriteHeaderBypass() throws IOException {
        protectedAdminWithBypass("none");
        when(httpClient.getWithStatusNoAuth(anyString(), anyMap())).thenAnswer(inv -> {
            Map<String, String> headers = inv.getArgument(1);
            if ("/admin".equals(headers.get("X-Original-URL"))) {
                return new HttpResponse(200, "{\"users\":[{\"id\":1,\"role\":\"admin\"}]}", Map.of());
            }
            return new HttpResponse(200, "{\"status\":\"ok\"}", Map.of());
        });

        List<Finding> findings = bypassFindings(testCase.execute(usersEndpoint(), httpClient));

        assertEquals(1, findings.size());
        assertTrue(findings.get(0).getRequestDetails().contains("X-Original-URL: /admin"));
    }

    @Test
    @DisplayName("Rewrite header that is ignored (same body as '/') is not reported")
    void testIgnoredRewriteHeaderIsQuiet() throws IOException {
        protectedAdminWithBypass("none");
        when(httpClient.getWithStatusNoAuth(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"status\":\"ok\"}", Map.of()));

        assertTrue(bypassFindings(testCase.execute(usersEndpoint(), httpClient)).isEmpty());
    }

    @Test
    @DisplayName("No bypass variants are sent when the admin path does not exist")
    void testNoBypassWhenAdminPathMissing() throws IOException {
        when(httpClient.getWithStatusNoAuth(anyString()))
                .thenReturn(new HttpResponse(404, "{\"error\":\"not found\"}", Map.of()));
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "{}", Map.of()));

        assertTrue(bypassFindings(testCase.execute(usersEndpoint(), httpClient)).isEmpty());
        verify(httpClient, never()).getWithStatusNoAuth(BASE + "/admin;/");
        verify(httpClient, never()).getWithStatusNoAuth(anyString(), anyMap());
    }

    @Test
    @DisplayName("Bypass variants for an admin path are sent once per scan, not once per endpoint")
    void testBypassVariantsSentOncePerScan() throws IOException {
        protectedAdminWithBypass("none");
        EndpointInfo other = new EndpointInfo("/api/orders", "POST");
        other.setBaseUrl(BASE);

        testCase.execute(usersEndpoint(), httpClient);
        testCase.execute(other, httpClient);

        verify(httpClient, times(1)).getWithStatusNoAuth(BASE + "/admin;/");
    }

    @Test
    @DisplayName("Path variants survive client-side normalisation")
    void testPathBypassVariants() {
        assertEquals(List.of("//admin", "/admin/", "/admin;/", "/admin..;/", "/%61dmin", "/ADMIN", "/admin%20"),
                BrokenFunctionLevelAuthorizationTestCase.pathBypassVariants("/admin"));
    }
}
