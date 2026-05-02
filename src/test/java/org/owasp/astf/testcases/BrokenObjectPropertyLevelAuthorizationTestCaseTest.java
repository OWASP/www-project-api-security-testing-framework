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
 * Unit tests for {@link BrokenObjectPropertyLevelAuthorizationTestCase}.
 *
 * <p>Covers excessive data exposure (sensitive fields in GET responses) and mass-assignment
 * privilege escalation via POST/PUT/PATCH bodies (issue #34).</p>
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/">OWASP API3:2023</a>
 */
@DisplayName("BrokenObjectPropertyLevelAuthorization test case")
class BrokenObjectPropertyLevelAuthorizationTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private BrokenObjectPropertyLevelAuthorizationTestCase testCase;

    // ── helpers ───────────────────────────────────────────────────────────────

    private static HttpResponse ok(String body) {
        return new HttpResponse(200, body, Map.of());
    }

    private static HttpResponse unauthorized() {
        return new HttpResponse(401, "{\"error\":\"unauthorized\"}", Map.of());
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenObjectPropertyLevelAuthorizationTestCase();
    }

    // ── metadata ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getId / getName / getDescription return expected values")
    void metadata() {
        assertEquals("ASTF-API3-2023", testCase.getId());
        assertEquals("Broken Object Property Level Authorization", testCase.getName());
        assertFalse(testCase.getDescription().isBlank());
    }

    // ── excessive data exposure (GET) ────────────────────────────────────────

    /**
     * A GET response containing the field {@code "password"} should trigger an
     * Excessive Data Exposure finding at HIGH severity.
     */
    @Test
    @DisplayName("Flags response exposing sensitive field 'password'")
    void detectsSensitiveFieldInResponse() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v1/users/1", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(ok("{\"id\":1,\"name\":\"Alice\",\"password\":\"s3cr3t\"}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect exposed sensitive field");
        Finding f = findings.get(0);
        assertEquals("Excessive Data Exposure - Sensitive Fields in Response", f.getTitle());
        assertEquals(Severity.HIGH, f.getSeverity());
        assertTrue(f.getEvidence().contains("password"),
                "Evidence should name the exposed field");
    }

    /**
     * A GET response containing no sensitive fields should not produce any excessive-data-exposure finding.
     */
    @Test
    @DisplayName("No finding when GET response contains no sensitive fields")
    void noFindingForCleanResponse() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v1/users/1", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(ok("{\"id\":1,\"name\":\"Alice\",\"email\":\"a@example.com\"}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Clean response should produce no findings");
    }

    /**
     * Non-GET endpoints should not trigger the excessive-data-exposure check.
     */
    @Test
    @DisplayName("Skips excessive-data-exposure check for non-GET endpoints")
    void skipsExcessiveDataCheckForNonGet() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v1/users", "POST");

        // Even if the response body contained a sensitive field, the check is skipped for POST
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"id\":2,\"password\":\"oops\"}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Only mass-assignment findings would apply here; excessive data exposure should be absent
        assertFalse(findings.stream().anyMatch(
                        f -> f.getTitle().contains("Excessive Data Exposure")),
                "POST endpoint should not trigger Excessive Data Exposure check");
    }

    // ── mass assignment (POST / PUT / PATCH) ─────────────────────────────────

    /**
     * When a POST body with {@code isAdmin:true} is reflected in the response, a mass-assignment
     * finding at HIGH severity should be raised.
     */
    @Test
    @DisplayName("Flags mass-assignment privilege escalation via POST")
    void detectsMassAssignmentOnPost() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v1/users", "POST");

        // Server echoes back the payload including the isAdmin field → privilege accepted
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"id\":3,\"name\":\"Bob\",\"isAdmin\":true,\"role\":\"admin\"}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(
                        f -> "Mass Assignment - Privilege Escalation via Object Properties".equals(f.getTitle())),
                "Should detect mass-assignment via POST");

        findings.stream()
                .filter(f -> f.getTitle().contains("Mass Assignment"))
                .findFirst()
                .ifPresent(f -> assertEquals(Severity.HIGH, f.getSeverity()));
    }

    /**
     * When the server accepts the POST body but does not reflect the privileged properties,
     * no mass-assignment finding should be raised.
     */
    @Test
    @DisplayName("No mass-assignment finding when server does not reflect privileged properties")
    void noMassAssignmentWhenPropertiesNotReflected() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v1/users", "POST");

        // Server returns 200 but does NOT echo back isAdmin or role
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(ok("{\"id\":4,\"name\":\"Carol\",\"email\":\"c@example.com\"}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.stream().anyMatch(
                        f -> f.getTitle().contains("Mass Assignment")),
                "Should not flag mass assignment when privileged fields are not reflected");
    }

    /**
     * GET endpoints should be skipped by the mass-assignment check (only POST/PUT/PATCH apply).
     */
    @Test
    @DisplayName("GET endpoints are not tested for mass assignment")
    void skipsMassAssignmentForGet() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/v1/users", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(ok("{\"id\":1,\"name\":\"Alice\"}"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.stream().anyMatch(
                        f -> f.getTitle().contains("Mass Assignment")),
                "GET endpoint should not trigger mass-assignment test");
    }
}
