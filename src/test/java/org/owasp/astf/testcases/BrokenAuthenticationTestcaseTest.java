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
import org.owasp.astf.core.result.Finding;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link BrokenAuthenticationTestCase} class.
 *
 * These tests validate that the test case correctly identifies various authentication
 * vulnerabilities according to OWASP API Security Top 10 2023: API2 - Broken Authentication.
 *
 * The tests cover:
 * - Identification of authentication endpoints
 * - Detection of missing authentication controls
 * - Testing for token vulnerabilities
 * - Handling of different HTTP methods
 * - Proper error and exception handling
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API Security - Broken Authentication</a>
 */
@DisplayName("Broken Authentication Test Case Tests")
class BrokenAuthenticationTestCaseTest {

    /**
     * Mocked HTTP client for simulating API responses.
     */
    @Mock
    private HttpClient httpClient;

    /**
     * The test case instance being tested.
     */
    private BrokenAuthenticationTestCase testCase;

    /**
     * Sets up the test environment before each test.
     * Initializes mocks and creates a fresh instance of the test case.
     */
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new BrokenAuthenticationTestCase();
    }

    /**
     * Tests that the test case returns the correct ID, name, and description.
     * These properties are crucial for proper identification and reporting.
     */
    @Test
    @DisplayName("Test case should have correct ID, name, and description")
    void testIdAndName() {
        // Verify test case identification properties
        assertEquals("ASTF-API2-2023", testCase.getId(), "Test case ID should match OWASP enumeration");
        assertEquals("Broken Authentication", testCase.getName(), "Test case name should be descriptive");

        // Verify description exists and contains key information
        String description = testCase.getDescription();
        assertNotNull(description, "Description should not be null");
        assertTrue(description.contains("authentication"),
                "Description should mention authentication");
    }

    /**
     * Tests that authentication endpoints are correctly identified and handled.
     * Auth endpoints with POST methods should be flagged for review, while
     * others should be processed differently.
     *
     * @param path The API endpoint path
     * @param method The HTTP method
     * @param isAuth Whether this should be detected as an auth endpoint
     * @throws IOException If an I/O error occurs during testing
     */
    @ParameterizedTest(name = "{0} with {1} method, isAuth={2}")
    @MethodSource("provideAuthEndpoints")
    @DisplayName("Should correctly identify and test authentication endpoints")
    void testAuthEndpoints(String path, String method, boolean isAuth) throws IOException {
        // Set up test endpoint
        EndpointInfo endpoint = new EndpointInfo(path, method);

        // Mock HTTP response for POST authentication endpoints
        if (method.equals("POST") && isAuth) {
            when(httpClient.post(anyString(), anyMap(), anyString(), anyString()))
                    .thenReturn("{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"}");
        }

        // Execute the test case
        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Verify results based on endpoint type and method
        if (isAuth && method.equals("POST")) {
            // Authentication endpoints with POST should be flagged for review
            assertFalse(findings.isEmpty(), "Auth endpoints should produce findings");
            assertEquals(1, findings.size(), "Should have one finding for auth endpoint");
            assertEquals("Authentication Endpoint Requires Manual Review", findings.get(0).getTitle(),
                    "Finding should indicate manual review needed");
        } else if (isAuth) {
            // Auth endpoints with non-POST methods should not produce findings
            assertTrue(findings.isEmpty(), "Non-POST auth endpoints should not produce findings");
        }
    }

    /**
     * Provides test data for authentication endpoint tests.
     * Includes various endpoint paths with different HTTP methods and expected outcomes.
     *
     * @return Stream of arguments for parameterized tests
     */
    private static Stream<Arguments> provideAuthEndpoints() {
        return Stream.of(
                // Format: path, HTTP method, isAuthEndpoint

                // Common authentication endpoints with POST
                Arguments.of("/api/login", "POST", true),
                Arguments.of("/api/auth/token", "POST", true),
                Arguments.of("/api/signin", "POST", true),

                // Auth endpoints with other methods
                Arguments.of("/api/login", "GET", true),

                // Non-auth endpoints
                Arguments.of("/api/products", "GET", false),
                Arguments.of("/api/users", "POST", false)
        );
    }

    /**
     * Tests detection of successful access without authentication.
     * When an endpoint that requires authentication returns data without auth,
     * it should be flagged as a vulnerability.
     *
     * @throws IOException If an I/O error occurs during testing
     */
    @Test
    @DisplayName("Should detect endpoints missing authentication controls")
    void testMissingAuthenticationSuccess() throws IOException {
        // Create an endpoint that should require authentication
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET", "application/json", null, true);

        // Mock a 200 OK response with data, indicating no auth check
        when(httpClient.get(anyString(), anyMap()))
                .thenReturn("{\"users\":[{\"id\":1,\"name\":\"Admin\"}]}");

        // Execute the test case
        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Verify a vulnerability was detected
        assertFalse(findings.isEmpty(), "Should find missing authentication");
        assertEquals(1, findings.size(), "Should have one finding");
        assertEquals("Missing Authentication Controls", findings.get(0).getTitle(),
                "Finding should indicate missing auth controls");
    }

    /**
     * Tests that properly authenticated endpoints are not flagged.
     * When an endpoint correctly returns an unauthorized error,
     * no findings should be reported.
     *
     * @throws IOException If an I/O error occurs during testing
     */
    @Test
    @DisplayName("Should not flag endpoints with proper authentication")
    void testMissingAuthenticationProtected() throws IOException {
        // Create an endpoint that should require authentication
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET", "application/json", null, true);

        // Mock a response with unauthorized error, indicating proper auth check
        when(httpClient.get(anyString(), anyMap()))
                .thenReturn("{\"error\":\"unauthorized\",\"message\":\"Authentication required\"}");

        // Execute the test case
        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Verify no vulnerabilities were detected
        assertTrue(findings.isEmpty(), "Should not report findings for properly protected endpoints");
    }

    /**
     * Tests proper exception handling during authentication testing.
     * When HTTP requests fail with exceptions, the test case should handle them gracefully.
     *
     * @throws IOException If an I/O error occurs during testing
     */
    @Test
    @DisplayName("Should handle exceptions gracefully during testing")
    void testMissingAuthenticationException() throws IOException {
        // Create an endpoint that should require authentication
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET", "application/json", null, true);

        // Mock an exception during the HTTP request
        when(httpClient.get(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        // Execute the test case - should not throw exceptions
        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Verify no vulnerabilities were reported due to the exception
        assertTrue(findings.isEmpty(), "Should not report findings when exceptions occur");
    }

    /**
     * Tests missing authentication detection across different HTTP methods.
     * Each HTTP method (GET, POST, PUT, DELETE) should be tested for auth vulnerabilities.
     *
     * @param method The HTTP method to test
     * @throws IOException If an I/O error occurs during testing
     */
    @ParameterizedTest(name = "Testing {0} method")
    @MethodSource("provideHttpMethods")
    @DisplayName("Should detect missing authentication for all HTTP methods")
    void testMissingAuthenticationForDifferentMethods(String method) throws IOException {
        // Create an endpoint with the specified HTTP method
        EndpointInfo endpoint = new EndpointInfo("/api/resources", method, "application/json", null, true);

        // Mock successful responses for the HTTP method
        switch (method) {
            case "GET" -> when(httpClient.get(anyString(), anyMap()))
                    .thenReturn("{\"data\":\"success\"}");
            case "POST" -> when(httpClient.post(anyString(), anyMap(), anyString(), anyString()))
                    .thenReturn("{\"data\":\"success\"}");
            case "PUT" -> when(httpClient.put(anyString(), anyMap(), anyString(), anyString()))
                    .thenReturn("{\"data\":\"success\"}");
            case "DELETE" -> when(httpClient.delete(anyString(), anyMap()))
                    .thenReturn("{\"data\":\"success\"}");
        }

        // Execute the test case
        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Verify a vulnerability was detected
        assertFalse(findings.isEmpty(), "Should find missing authentication for " + method);
        assertEquals(1, findings.size(), "Should have one finding");
        assertEquals("Missing Authentication Controls", findings.get(0).getTitle(),
                "Finding should indicate missing auth controls");
    }

    /**
     * Provides HTTP methods for parameterized tests.
     *
     * @return Stream of HTTP methods to test
     */
    private static Stream<Arguments> provideHttpMethods() {
        return Stream.of(
                Arguments.of("GET"),
                Arguments.of("POST"),
                Arguments.of("PUT"),
                Arguments.of("DELETE")
        );
    }

    /**
     * Tests that endpoints not requiring authentication are skipped.
     * Public endpoints should not be flagged for missing authentication.
     *
     * @throws IOException If an I/O error occurs during testing
     */
    @Test
    @DisplayName("Should skip endpoints that don't require authentication")
    void testEndpointNotRequiringAuth() throws IOException {
        // Create an endpoint that doesn't require authentication (isRequiresAuthentication=false)
        EndpointInfo endpoint = new EndpointInfo("/api/public", "GET", "application/json", null, false);

        // Execute the test case
        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Verify no vulnerabilities were reported
        assertTrue(findings.isEmpty(), "Should not test endpoints that don't require authentication");
    }

    /**
     * Tests token vulnerability detection functionality.
     * Note: The current implementation returns an empty list, but this test ensures
     * the code path is executed and allows for future expansion.
     *
     * @throws IOException If an I/O error occurs during testing
     */
    @Test
    @DisplayName("Should handle token vulnerability testing")
    void testTokenVulnerabilities() throws IOException {
        // Create an endpoint for token testing
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET", "application/json", null, true);

        // Mock an unauthorized response
        when(httpClient.get(anyString(), anyMap()))
                .thenReturn("{\"error\":\"unauthorized\"}");

        // Execute the test case
        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Verify the current implementation (no findings for token vulnerabilities yet)
        assertTrue(findings.isEmpty(), "Current implementation should not find token vulnerabilities");

        // Note: This test allows for future expansion of token vulnerability testing
    }

    /**
     * Tests that different HTTP methods on the same endpoint are tested independently.
     * Each HTTP method should be evaluated separately for auth vulnerabilities.
     *
     * @throws IOException If an I/O error occurs during testing
     */
    @Test
    @DisplayName("Should test different methods on same endpoint independently")
    void testMultipleMethodsOnSameEndpoint() throws IOException {
        // Create endpoints for GET and POST on the same path
        EndpointInfo getEndpoint = new EndpointInfo("/api/resources", "GET", "application/json", null, true);
        EndpointInfo postEndpoint = new EndpointInfo("/api/resources", "POST", "application/json", "{}", true);

        // Mock responses: GET succeeds without auth, POST properly requires auth
        when(httpClient.get(anyString(), anyMap()))
                .thenReturn("{\"data\":\"success\"}");

        when(httpClient.post(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn("{\"error\":\"unauthorized\"}");

        // Execute the test cases
        List<Finding> getFindings = testCase.execute(getEndpoint, httpClient);
        List<Finding> postFindings = testCase.execute(postEndpoint, httpClient);

        // Verify GET has vulnerabilities but POST doesn't
        assertFalse(getFindings.isEmpty(), "Should find issues with GET method");
        assertTrue(postFindings.isEmpty(), "Should not find issues with POST method");
    }
}