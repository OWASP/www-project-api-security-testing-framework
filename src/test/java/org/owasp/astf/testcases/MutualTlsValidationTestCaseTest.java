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

@DisplayName("Mutual TLS Validation Test Case Tests")
class MutualTlsValidationTestCaseTest {

    @Mock private HttpClient httpClient;
    private MutualTlsValidationTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new MutualTlsValidationTestCase();
    }

    @Test
    @DisplayName("Should have correct metadata")
    void testMetadata() {
        assertEquals("ASTF-MTLS-2023", testCase.getId());
        assertEquals("Mutual TLS Validation", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Should skip entirely for non-HTTPS endpoints")
    void testSkipsNonHttpsEndpoints() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        endpoint.setBaseUrl("http://example.com");

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not run mTLS checks against a plain HTTP endpoint");
    }

    @Test
    @DisplayName("Should skip when no client certificate is configured")
    void testSkipsWhenNoClientCertConfigured() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.hasClientCert()).thenReturn(false);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not run mTLS checks without --client-cert configured");
    }

    @Test
    @DisplayName("Should skip the arbitrary-certificate check when no invalid cert is configured")
    void testSkipsWhenNoInvalidCertConfigured() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.hasClientCert()).thenReturn(true);
        when(httpClient.hasInvalidClientCert()).thenReturn(false);

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not attempt the comparison without --invalid-client-cert");
    }

    @Test
    @DisplayName("Should flag arbitrary certificate acceptance when the invalid cert is accepted like the valid one")
    void testDetectsArbitraryCertificateAcceptance() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.hasClientCert()).thenReturn(true);
        when(httpClient.hasInvalidClientCert()).thenReturn(true);
        when(httpClient.getClientCertPath()).thenReturn("/certs/valid.p12");
        when(httpClient.getClientCertPassword()).thenReturn("validpass");
        when(httpClient.getInvalidClientCertPath()).thenReturn("/certs/invalid.p12");
        when(httpClient.getInvalidClientCertPassword()).thenReturn("invalidpass");

        when(httpClient.getWithClientCert(anyString(), anyMap(), eq("/certs/valid.p12"), eq("validpass")))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.getWithClientCert(anyString(), anyMap(), eq("/certs/invalid.p12"), eq("invalidpass")))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Arbitrary Client Certificate Accepted")),
                "Should flag that an untrusted certificate was accepted identically to the valid one");
        findings.stream()
                .filter(f -> f.getTitle().contains("Arbitrary Client Certificate Accepted"))
                .findFirst()
                .ifPresent(f -> assertEquals(Severity.CRITICAL, f.getSeverity()));
    }

    @Test
    @DisplayName("Should NOT flag anything when the invalid certificate is correctly rejected at the TLS handshake")
    void testNoFindingWhenInvalidCertRejectedAtHandshake() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.hasClientCert()).thenReturn(true);
        when(httpClient.hasInvalidClientCert()).thenReturn(true);
        when(httpClient.getClientCertPath()).thenReturn("/certs/valid.p12");
        when(httpClient.getInvalidClientCertPath()).thenReturn("/certs/invalid.p12");

        when(httpClient.getWithClientCert(anyString(), anyMap(), eq("/certs/valid.p12"), any()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        // The TLS handshake itself fails for the untrusted certificate — correct server behavior.
        when(httpClient.getWithClientCert(anyString(), anyMap(), eq("/certs/invalid.p12"), any()))
                .thenThrow(new IOException("javax.net.ssl.SSLHandshakeException: certificate_unknown"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag anything when the invalid cert is rejected at the TLS layer");
    }

    @Test
    @DisplayName("Should NOT flag anything when the invalid certificate is correctly rejected at the application layer")
    void testNoFindingWhenInvalidCertRejectedByApplication() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.hasClientCert()).thenReturn(true);
        when(httpClient.hasInvalidClientCert()).thenReturn(true);
        when(httpClient.getClientCertPath()).thenReturn("/certs/valid.p12");
        when(httpClient.getInvalidClientCertPath()).thenReturn("/certs/invalid.p12");

        when(httpClient.getWithClientCert(anyString(), anyMap(), eq("/certs/valid.p12"), any()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.getWithClientCert(anyString(), anyMap(), eq("/certs/invalid.p12"), any()))
                .thenReturn(new HttpResponse(403, "{\"error\":\"forbidden\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag anything when the invalid cert is correctly rejected with 403");
    }

    @Test
    @DisplayName("Should handle exceptions gracefully")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/data", "GET");
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.hasClientCert()).thenReturn(true);
        when(httpClient.hasInvalidClientCert()).thenReturn(true);
        when(httpClient.getWithClientCert(anyString(), anyMap(), any(), any()))
                .thenThrow(new RuntimeException("Unexpected error"));

        List<Finding> findings = assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        assertNotNull(findings);
    }
}
