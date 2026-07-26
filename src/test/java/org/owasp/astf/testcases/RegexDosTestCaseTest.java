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

@DisplayName("RegexDosTestCase unit tests")
class RegexDosTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private RegexDosTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new RegexDosTestCase();
    }

    @Test
    @DisplayName("getId / getName / getDescription return expected values")
    void testMetadata() {
        assertEquals("ASTF-REDOS-2023", testCase.getId());
        assertEquals("Regular Expression Denial of Service (ReDoS)", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Skips GET endpoints entirely — ReDoS only tested against body-carrying methods")
    void testSkipsGetEndpoints() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Does not flag ReDoS when every response is fast")
    void testNoFindingWhenFast() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1/email", "PUT", "application/json",
                "{\"email\":\"a@b.com\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"updated\":true}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects ReDoS when the payload request times out (IOException)")
    void testDetectsReDosViaTimeout() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1/email", "PUT", "application/json",
                "{\"email\":\"a@b.com\"}", true);
        endpoint.setBaseUrl("https://example.com");

        // Baseline (benign "test" value) succeeds fast; any call containing the long ReDoS
        // payload (35 repeated characters) times out instead.
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && !body.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        && !body.contains("11111111111111111111111111111111111"))))
                .thenReturn(new HttpResponse(200, "{\"updated\":true}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && (body.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        || body.contains("11111111111111111111111111111111111")))))
                .thenThrow(new IOException("Read timed out"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect ReDoS from the timeout");
        assertEquals("Regular Expression Denial of Service (ReDoS)", findings.get(0).getTitle());
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Handles exceptions gracefully when the baseline request itself fails")
    void testHandlesBaselineFailureGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1/email", "PUT", "application/json",
                "{\"email\":\"a@b.com\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "Should skip gracefully when even the baseline can't be established");
    }
}
