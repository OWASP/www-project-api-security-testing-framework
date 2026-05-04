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
 * Unit tests for {@link GrpcEndpointDetectionTestCase}.
 *
 * <p>Covers gRPC endpoint detection via content-type headers, server reflection
 * detection, non-gRPC endpoint handling, and exception safety.</p>
 */
@DisplayName("GrpcEndpointDetectionTestCase unit tests")
class GrpcEndpointDetectionTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private GrpcEndpointDetectionTestCase testCase;

    // ── helpers ───────────────────────────────────────────────────────────────

    /** 200 response with application/grpc content-type — looks like a gRPC service */
    private static HttpResponse grpcResponse() {
        return new HttpResponse(200, "", Map.of("content-type", List.of("application/grpc")));
    }

    /** 200 response with application/grpc+proto variant */
    private static HttpResponse grpcProtoResponse() {
        return new HttpResponse(200, "", Map.of("content-type", List.of("application/grpc+proto")));
    }

    /** 200 response with a plain JSON content-type — not a gRPC service */
    private static HttpResponse jsonResponse() {
        return new HttpResponse(200, "{}", Map.of("content-type", List.of("application/json")));
    }

    /** 404 response with no gRPC content-type */
    private static HttpResponse notFound() {
        return new HttpResponse(404, "", Map.of());
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new GrpcEndpointDetectionTestCase();
    }

    // ── metadata ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getId / getName / getDescription return expected values")
    void testMetadata() {
        assertEquals("ASTF-GRPC-2023", testCase.getId());
        assertEquals("gRPC Endpoint Detection", testCase.getName());
        assertNotNull(testCase.getDescription());
        assertFalse(testCase.getDescription().isBlank());
    }

    // ── isGrpcResponse ────────────────────────────────────────────────────────

    @Test
    @DisplayName("isGrpcResponse returns true for application/grpc content-type")
    void testIsGrpcResponseTrue() {
        assertTrue(testCase.isGrpcResponse(grpcResponse()));
    }

    @Test
    @DisplayName("isGrpcResponse returns true for application/grpc+proto content-type")
    void testIsGrpcResponseProtoVariant() {
        assertTrue(testCase.isGrpcResponse(grpcProtoResponse()));
    }

    @Test
    @DisplayName("isGrpcResponse returns false for application/json content-type")
    void testIsGrpcResponseFalseForJson() {
        assertFalse(testCase.isGrpcResponse(jsonResponse()));
    }

    @Test
    @DisplayName("isGrpcResponse returns false when headers are null")
    void testIsGrpcResponseNullHeaders() {
        HttpResponse response = new HttpResponse(200, "", null);
        assertFalse(testCase.isGrpcResponse(response));
    }

    @Test
    @DisplayName("isGrpcResponse is case-insensitive for content-type header name")
    void testIsGrpcResponseCaseInsensitive() {
        // Header name in mixed case
        HttpResponse response = new HttpResponse(200, "",
                Map.of("Content-Type", List.of("application/grpc")));
        assertTrue(testCase.isGrpcResponse(response));
    }

    // ── detectGrpcEndpoint ────────────────────────────────────────────────────

    @Test
    @DisplayName("detectGrpcEndpoint emits INFO finding when gRPC content-type is detected")
    void testDetectGrpcEndpointFound() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.health.v1.Health/Check", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(grpcResponse());

        List<Finding> findings = testCase.detectGrpcEndpoint(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should emit a finding when gRPC is detected");
        Finding f = findings.get(0);
        assertEquals("gRPC Endpoint Detected — Manual Security Review Required", f.getTitle());
        assertEquals(Severity.INFO, f.getSeverity());
    }

    @Test
    @DisplayName("detectGrpcEndpoint returns no findings when no gRPC content-type present")
    void testDetectGrpcEndpointNotFound() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(notFound());

        List<Finding> findings = testCase.detectGrpcEndpoint(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not emit findings for non-gRPC endpoints");
    }

    @Test
    @DisplayName("detectGrpcEndpoint returns at most one finding (breaks after first detection)")
    void testDetectGrpcEndpointOnlyOneFinding() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.health.v1.Health/Check", "POST");

        // All probes succeed — but we should only get one finding
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(grpcResponse());

        List<Finding> findings = testCase.detectGrpcEndpoint(endpoint, httpClient);

        assertEquals(1, findings.size(), "Should emit exactly one detection finding");
    }

    @Test
    @DisplayName("detectGrpcEndpoint handles IOException without propagating it")
    void testDetectGrpcEndpointExceptionHandled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.health.v1.Health/Check", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> testCase.detectGrpcEndpoint(endpoint, httpClient),
                "IOException should be caught and not propagated");
    }

    // ── detectServerReflection ────────────────────────────────────────────────

    @Test
    @DisplayName("detectServerReflection emits MEDIUM finding when reflection service responds")
    void testDetectServerReflectionEnabled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(grpcResponse());

        List<Finding> findings = testCase.detectServerReflection(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect gRPC server reflection");
        Finding f = findings.get(0);
        assertEquals("gRPC Server Reflection Enabled", f.getTitle());
        assertEquals(Severity.MEDIUM, f.getSeverity());
        assertNotNull(f.getEvidence());
        assertTrue(f.getEvidence().contains("application/grpc"));
    }

    @Test
    @DisplayName("detectServerReflection returns no findings when reflection is not active")
    void testDetectServerReflectionNotEnabled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(notFound());

        List<Finding> findings = testCase.detectServerReflection(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag when reflection service is absent");
    }

    @Test
    @DisplayName("detectServerReflection handles IOException without propagating it")
    void testDetectServerReflectionExceptionHandled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> testCase.detectServerReflection(endpoint, httpClient),
                "IOException should be caught and not propagated");
    }

    // ── execute (integration) ─────────────────────────────────────────────────

    @Test
    @DisplayName("execute returns both detection and reflection findings when both are present")
    void testExecuteBothFindingsPresent() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.health.v1.Health/Check", "POST");

        // All probes (detection + reflection) respond with gRPC content-type
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(grpcResponse());

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        // Should include at least one detection (INFO) and one reflection (MEDIUM) finding
        assertTrue(findings.size() >= 2, "Should return at least 2 findings");
        assertTrue(findings.stream().anyMatch(f -> f.getSeverity() == Severity.INFO),
                "Should include an INFO finding for gRPC detection");
        assertTrue(findings.stream().anyMatch(f -> f.getSeverity() == Severity.MEDIUM),
                "Should include a MEDIUM finding for server reflection");
    }

    @Test
    @DisplayName("execute handles IOException without propagating it")
    void testExecuteExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Network error"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient),
                "execute() should not propagate IOException");
    }
}
