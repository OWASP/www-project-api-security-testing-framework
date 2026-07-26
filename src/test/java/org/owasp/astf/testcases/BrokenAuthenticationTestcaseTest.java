package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BrokenAuthenticationTestCase} (OWASP API2:2023 Broken Authentication).
 */
@DisplayName("Broken Authentication Test Case Tests")
class BrokenAuthenticationTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private BrokenAuthenticationTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenAuthenticationTestCase();
    }

    @Test
    @DisplayName("Test case should have correct ID, name, and description")
    void testIdAndName() {
        assertEquals("ASTF-API2-2023", testCase.getId());
        assertEquals("Broken Authentication", testCase.getName());
        String description = testCase.getDescription();
        assertNotNull(description);
        assertTrue(description.contains("authentication"));
    }

    @ParameterizedTest(name = "{0} with {1} method, isAuth={2}")
    @MethodSource("provideAuthEndpoints")
    @DisplayName("Should correctly identify and test authentication endpoints")
    void testAuthEndpoints(String path, String method, boolean isAuth) throws IOException {
        EndpointInfo endpoint = new EndpointInfo(path, method);

        if (method.equals("POST") && isAuth) {
            // All credential attempts are rejected (401) — triggers the "manual review" finding
            when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                    .thenReturn(new HttpResponse(401, "{\"error\":\"Unauthorized\"}", Map.of()));
        }

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        if (isAuth && method.equals("POST")) {
            assertFalse(findings.isEmpty(), "Auth endpoints should produce findings");
            assertTrue(findings.stream().anyMatch(f ->
                            "Authentication Endpoint Requires Manual Review".equals(f.getTitle())),
                    "Should include the manual-review finding when no weak credentials are accepted");
            // Every attempt in this test returns 401 with no 429/423 lockout signal at any point —
            // testBruteForceLockout (#97) correctly flags that as a separate, additional finding.
            assertTrue(findings.stream().anyMatch(f ->
                            "No Account Lockout or Rate Limiting on Repeated Failed Logins".equals(f.getTitle())),
                    "Should flag missing lockout when 8 consecutive attempts never trigger one");
        } else if (isAuth) {
            assertTrue(findings.isEmpty(), "Non-POST auth endpoints should not produce findings");
        }
    }

    private static Stream<Arguments> provideAuthEndpoints() {
        return Stream.of(
                Arguments.of("/api/login",      "POST", true),
                Arguments.of("/api/auth/token", "POST", true),
                Arguments.of("/api/signin",     "POST", true),
                Arguments.of("/api/login",      "GET",  true),
                Arguments.of("/api/products",   "GET",  false),
                Arguments.of("/api/users",      "POST", false)
        );
    }

    @Test
    @DisplayName("Should detect endpoints missing authentication controls")
    void testMissingAuthenticationSuccess() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET", "application/json", null, true);

        // Server returns 200 without auth — indicates missing authentication controls
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"users\":[{\"id\":1,\"name\":\"Admin\"}]}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should find missing authentication");
        assertTrue(findings.stream().anyMatch(f -> "Missing Authentication Controls".equals(f.getTitle())),
                "Should have a Missing Authentication Controls finding");
    }

    @Test
    @DisplayName("Should not flag endpoints with proper authentication (401)")
    void testMissingAuthenticationProtected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET", "application/json", null, true);

        // Server correctly returns 401 when no auth header is present
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\",\"message\":\"Authentication required\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not report findings for properly protected endpoints");
    }

    @Test
    @DisplayName("Should handle exceptions gracefully during testing")
    void testMissingAuthenticationException() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET", "application/json", null, true);

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not report findings when exceptions occur");
    }

    @ParameterizedTest(name = "Testing {0} method")
    @MethodSource("provideHttpMethods")
    @DisplayName("Should detect missing authentication for all HTTP methods")
    void testMissingAuthenticationForDifferentMethods(String method) throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/resources", method, "application/json", null, true);

        HttpResponse successResponse = new HttpResponse(200, "{\"data\":\"success\"}", Map.of());

        switch (method) {
            case "GET"    -> when(httpClient.getWithStatus(anyString(), anyMap())).thenReturn(successResponse);
            case "POST"   -> when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString())).thenReturn(successResponse);
            case "PUT"    -> when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString())).thenReturn(successResponse);
            case "DELETE" -> when(httpClient.deleteWithStatus(anyString(), anyMap())).thenReturn(successResponse);
        }

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should find missing authentication for " + method);
        assertTrue(findings.stream().anyMatch(f -> "Missing Authentication Controls".equals(f.getTitle())),
                "Should have a Missing Authentication Controls finding for " + method);
    }

    private static Stream<Arguments> provideHttpMethods() {
        return Stream.of(
                Arguments.of("GET"),
                Arguments.of("POST"),
                Arguments.of("PUT"),
                Arguments.of("DELETE")
        );
    }

    @Test
    @DisplayName("Should skip endpoints that don't require authentication")
    void testEndpointNotRequiringAuth() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/public", "GET", "application/json", null, false);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not test endpoints that don't require authentication");
    }

    @Test
    @DisplayName("Should not report findings when server rejects all unauthenticated requests")
    void testTokenVulnerabilities() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET", "application/json", null, true);

        // Server correctly rejects all requests including none-alg JWT attempts
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not report findings when server rejects unauthenticated requests");
    }

    @Test
    @DisplayName("Should detect JWT none-algorithm vulnerability")
    void testJwtNoneAlgorithmDetection() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET", "application/json", null, true);

        // Server accepts requests with JWT none-algorithm (vulnerability!)
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    Map<String, String> hdrs = inv.getArgument(1);
                    String auth = hdrs.getOrDefault("Authorization", "");
                    // Accept the none-alg token but reject un-authenticated requests
                    if (auth.startsWith("Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0")) {
                        return new HttpResponse(200, "{\"data\":\"secret\"}", Map.of());
                    }
                    return new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect JWT none-algorithm acceptance");
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("JWT")),
                "Should have a JWT-related finding");
    }

    @Test
    @DisplayName("Should NOT flag JWT none-algorithm on public endpoints (false positive prevention)")
    void testJwtNoneAlgorithmNoFalsePositiveOnPublicEndpoint() throws IOException {
        // This is the root cause of the Rocket.Chat false positive:
        // /api/info returns 200 to everyone — the test must not flag it as a JWT-none bypass.
        EndpointInfo endpoint = new EndpointInfo("/api/info", "GET", "application/json", null, true);

        // Public endpoint — always returns 200 regardless of auth header (or lack thereof)
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"version\":\"8.5\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // "Missing Authentication Controls" finding is expected (endpoint is public when requiresAuth=true)
        // but there must be NO JWT 'none' or expired-JWT finding — those would be false positives
        assertFalse(
                findings.stream().anyMatch(f -> f.getTitle().contains("JWT")),
                "Should NOT report JWT 'none' or expired-JWT finding on a public endpoint " +
                "(baseline without auth already returns 200 — the JWT token is irrelevant)"
        );
    }

    @Test
    @DisplayName("Should include baseline HTTP status in JWT none finding evidence")
    void testJwtNoneEvidenceIncludesBaselineStatus() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/secret", "GET", "application/json", null, true);

        // Auth-required endpoint: rejects no-auth (401), accepts JWT-none (200)
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenAnswer(inv -> {
                    Map<String, String> hdrs = inv.getArgument(1);
                    String auth = hdrs.getOrDefault("Authorization", "");
                    if (auth.startsWith("Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0")) {
                        return new HttpResponse(200, "{\"data\":\"secret\"}", Map.of());
                    }
                    return new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream()
                .filter(f -> f.getTitle().contains("JWT") && f.getTitle().contains("none"))
                .anyMatch(f -> f.getEvidence() != null && f.getEvidence().contains("baseline")),
                "JWT 'none' finding evidence should mention the baseline HTTP status"
        );
    }

    @Test
    @DisplayName("Should NOT flag weak credentials when HTTP 200 body indicates the login actually failed (VAmPI-style false positive)")
    void testWeakCredentialsNoFalsePositiveOn200WithFailureBody() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/login", "POST", "application/json", "{}", true);

        // Mirrors VAmPI: login always returns HTTP 200, real result is in the body.
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"status\": \"fail\", \"message\": \"Username or Password Incorrect!\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> "Weak Default Credentials Accepted".equals(f.getTitle())),
                "Should not report weak credentials accepted when the response body says the login failed");
        assertTrue(findings.stream().noneMatch(f -> "2FA/MFA Bypass — Weak OTP Code Accepted".equals(f.getTitle())),
                "Should not report OTP bypass when the response body says the attempt failed");
    }

    @Test
    @DisplayName("Should still flag weak credentials when HTTP 200 body has no failure indicator")
    void testWeakCredentialsStillDetectedOnGenuineSuccess() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/users/v1/login", "POST", "application/json", "{}", true);

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"auth_token\": \"abc123\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> "Weak Default Credentials Accepted".equals(f.getTitle())),
                "Should still report weak credentials accepted on a genuine 200 success with no failure markers");
    }

    @Test
    @DisplayName("Should detect sensitive tokens exposed in URL query parameters")
    void testTokenInUrl() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data?token=abc123secret", "GET", "application/json", null, false);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect token in URL");
        assertTrue(findings.stream().anyMatch(f ->
                        f.getTitle().contains("Token") || f.getTitle().contains("URL")),
                "Should have a token-in-URL finding");
    }

    @Test
    @DisplayName("Should test different methods on same endpoint independently")
    void testMultipleMethodsOnSameEndpoint() throws IOException {
        EndpointInfo getEndpoint  = new EndpointInfo("/api/resources", "GET",  "application/json", null, true);
        EndpointInfo postEndpoint = new EndpointInfo("/api/resources", "POST", "application/json", "{}", true);

        // GET returns 200 (vulnerability), POST always returns 401 (correctly protected)
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"success\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));

        List<Finding> getFindings  = testCase.execute(getEndpoint,  httpClient);
        List<Finding> postFindings = testCase.execute(postEndpoint, httpClient);

        assertFalse(getFindings.isEmpty(), "Should find issues with GET method");
        // POST endpoint: both testMissingAuthentication and testJwtNoneAlgorithm use postWithStatus,
        // which returns 401, so no findings expected.
        assertTrue(postFindings.isEmpty(), "Should not find issues with POST method when server returns 401");
    }

    // ── user enumeration (#97) ───────────────────────────────────────────────

    @Test
    @DisplayName("Detects user enumeration when a common username's response differs from a random one")
    void testUserEnumerationDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/login", "POST");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("nonexistent_"))))
                .thenReturn(new HttpResponse(401, "{\"error\":\"No such user\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && body.contains("\"admin\""))))
                .thenReturn(new HttpResponse(401, "{\"error\":\"Incorrect password\"}", Map.of()));

        List<Finding> findings = testCase.testUserEnumeration(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("User Enumeration")),
                "Should detect enumeration from the differing 'no such user' vs 'incorrect password' messages");
    }

    @Test
    @DisplayName("Does not flag user enumeration when responses are identical")
    void testNoUserEnumerationWhenResponsesIdentical() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/login", "POST");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"Invalid username or password\"}", Map.of()));

        List<Finding> findings = testCase.testUserEnumeration(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag enumeration when every response is identical");
    }

    // ── brute-force lockout (#97) ─────────────────────────────────────────────

    @Test
    @DisplayName("Detects missing lockout when repeated failed logins never trigger rate limiting")
    void testMissingLockoutDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/login", "POST");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"Invalid username or password\"}", Map.of()));

        List<Finding> findings = testCase.testBruteForceLockout(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("No Account Lockout")),
                "Should flag missing lockout when no attempt is ever rate-limited");
    }

    @Test
    @DisplayName("Does not flag missing lockout when rate limiting kicks in")
    void testLockoutPresent() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/login", "POST");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"Invalid username or password\"}", Map.of()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"Invalid username or password\"}", Map.of()))
                .thenReturn(new HttpResponse(429, "{\"error\":\"Too many attempts\"}", Map.of()));

        List<Finding> findings = testCase.testBruteForceLockout(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag missing lockout once a 429 response is observed");
    }

    // ── JWT kid path traversal (#99) ──────────────────────────────────────────

    @Test
    @DisplayName("Detects JWT kid path traversal when a token signed with an empty secret is accepted")
    void testJwtKidPathTraversalDetected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/profile", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), eq(Map.of())))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));
        when(httpClient.getWithStatus(anyString(), argThat(h -> h != null && h.containsKey("Authorization"))))
                .thenReturn(new HttpResponse(200, "{\"data\":\"secret\"}", Map.of()));

        List<Finding> findings = testCase.testJwtKidPathTraversal(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect the kid path-traversal bypass");
        assertEquals("JWT 'kid' Path Traversal Accepted", findings.get(0).getTitle());
    }

    @Test
    @DisplayName("Does not flag JWT kid path traversal when the forged token is rejected")
    void testJwtKidPathTraversalNotDetectedWhenRejected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/profile", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));

        List<Finding> findings = testCase.testJwtKidPathTraversal(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Skips JWT kid path traversal test on publicly accessible endpoints")
    void testJwtKidPathTraversalSkippedOnPublicEndpoint() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/profile", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"public\"}", Map.of()));

        List<Finding> findings = testCase.testJwtKidPathTraversal(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "Should skip when baseline (no auth) already succeeds");
    }

    // ── JWT algorithm confusion (#99) ──────────────────────────────────────────

    @Test
    @DisplayName("Detects RS256-to-HS256 algorithm confusion when a JWKS is exposed and the forged token is accepted")
    void testJwtAlgorithmConfusionDetected() throws Exception {
        EndpointInfo endpoint = new EndpointInfo("/api/profile", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getModulus().toByteArray());
        String e = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getPublicExponent().toByteArray());
        String jwks = String.format("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"%s\"}]}", n, e);

        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("jwks")), anyMap()))
                .thenReturn(new HttpResponse(200, jwks, Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("jwks")), eq(Map.of())))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("jwks")),
                argThat(h -> h != null && h.containsKey("Authorization"))))
                .thenReturn(new HttpResponse(200, "{\"data\":\"secret\"}", Map.of()));

        List<Finding> findings = testCase.testJwtAlgorithmConfusion(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect algorithm confusion when the forged token is accepted");
        assertEquals("JWT Algorithm Confusion (RS256 to HS256) Accepted", findings.get(0).getTitle());
    }

    @Test
    @DisplayName("Skips JWT algorithm confusion test when no JWKS is exposed")
    void testJwtAlgorithmConfusionSkippedWithoutJwks() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/profile", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(404, "", Map.of()));

        List<Finding> findings = testCase.testJwtAlgorithmConfusion(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "Should skip without any exposed JWKS to build a forged token from");
    }

    // ── JWT jku processing detection (#99) ─────────────────────────────────────

    @Test
    @DisplayName("Detects jku header processing when the probe request times out")
    void testJwtJkuProcessingDetectedViaTimeout() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/profile", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), eq(Map.of())))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));
        when(httpClient.getWithStatus(anyString(), argThat(h -> h != null && h.containsKey("Authorization"))))
                .thenThrow(new IOException("Read timed out"));

        List<Finding> findings = testCase.testJwtJkuProcessing(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect jku processing from the timeout");
        assertTrue(findings.get(0).getTitle().contains("jku"));
    }

    @Test
    @DisplayName("Does not flag jku processing when the response is fast and unremarkable")
    void testJwtJkuProcessingNotDetectedWhenFast() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/profile", "GET", "application/json", null, true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of()));

        List<Finding> findings = testCase.testJwtJkuProcessing(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }
}
