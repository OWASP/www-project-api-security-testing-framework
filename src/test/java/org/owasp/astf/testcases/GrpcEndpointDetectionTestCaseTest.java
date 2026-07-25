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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
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

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(notFound());

        List<Finding> findings = testCase.detectGrpcEndpoint(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not emit findings for non-gRPC endpoints");
    }

    @Test
    @DisplayName("detectGrpcEndpoint returns at most one finding (breaks after first detection)")
    void testDetectGrpcEndpointOnlyOneFinding() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.health.v1.Health/Check", "POST");

        // All probes succeed — but we should only get one finding
        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(grpcResponse());

        List<Finding> findings = testCase.detectGrpcEndpoint(endpoint, httpClient);

        assertEquals(1, findings.size(), "Should emit exactly one detection finding");
    }

    @Test
    @DisplayName("detectGrpcEndpoint handles IOException without propagating it")
    void testDetectGrpcEndpointExceptionHandled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.health.v1.Health/Check", "POST");

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> testCase.detectGrpcEndpoint(endpoint, httpClient),
                "IOException should be caught and not propagated");
    }

    // ── detectServerReflection ────────────────────────────────────────────────

    @Test
    @DisplayName("detectServerReflection emits MEDIUM finding when reflection service responds")
    void testDetectServerReflectionEnabled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "POST");

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
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

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(notFound());

        List<Finding> findings = testCase.detectServerReflection(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not flag when reflection service is absent");
    }

    @Test
    @DisplayName("detectServerReflection handles IOException without propagating it")
    void testDetectServerReflectionExceptionHandled() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "POST");

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        assertDoesNotThrow(() -> testCase.detectServerReflection(endpoint, httpClient),
                "IOException should be caught and not propagated");
    }

    // ── gRPC reflection service enumeration (hand-rolled protobuf) ───────────
    //
    // Test-side protobuf/gRPC-frame encoders below are written independently from the
    // production code's encoders (rather than reusing them) so a bug shared between
    // production and test code can't hide a real defect from these tests.

    private static byte[] encodeVarint(long value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            if ((value & ~0x7FL) == 0) {
                out.write((int) value);
                break;
            } else {
                out.write((int) ((value & 0x7F) | 0x80));
                value >>>= 7;
            }
        }
        return out.toByteArray();
    }

    private static byte[] encodeLengthDelimitedField(int fieldNumber, byte[] value) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(encodeVarint(((long) fieldNumber << 3) | 2));
        out.write(encodeVarint(value.length));
        out.write(value);
        return out.toByteArray();
    }

    private static byte[] concatAll(byte[]... arrays) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] array : arrays) out.write(array);
        return out.toByteArray();
    }

    private static byte[] wrapGrpcFrame(byte[] message) {
        ByteBuffer buffer = ByteBuffer.allocate(5 + message.length);
        buffer.put((byte) 0);
        buffer.putInt(message.length);
        buffer.put(message);
        return buffer.array();
    }

    /** Builds a gRPC-framed ServerReflectionResponse{list_services_response{service:[...names]}}. */
    private static byte[] buildListServicesResponse(String... serviceNames) throws IOException {
        ByteArrayOutputStream listServiceResponse = new ByteArrayOutputStream();
        for (String name : serviceNames) {
            byte[] serviceResponse = encodeLengthDelimitedField(1, name.getBytes(StandardCharsets.UTF_8));
            listServiceResponse.write(encodeLengthDelimitedField(1, serviceResponse));
        }
        byte[] serverReflectionResponse = encodeLengthDelimitedField(6, listServiceResponse.toByteArray());
        return wrapGrpcFrame(serverReflectionResponse);
    }

    @Test
    @DisplayName("encodeListServicesRequest produces a valid gRPC-framed list_services request")
    void testEncodeListServicesRequest() {
        byte[] encoded = testCase.encodeListServicesRequest();

        // 5-byte gRPC frame header (0 compression flag + 4-byte big-endian length=2) + 2-byte message
        assertEquals(7, encoded.length);
        assertEquals(0, encoded[0], "Compression flag should be 0 (uncompressed)");
        ByteBuffer buffer = ByteBuffer.wrap(encoded, 1, 4);
        assertEquals(2, buffer.getInt(), "Message length should be 2 bytes");
        assertEquals(0x3A, encoded[5] & 0xFF, "Tag byte for field 7 (list_services), wire type 2");
        assertEquals(0x00, encoded[6] & 0xFF, "Zero-length string for list_services value");
    }

    @Test
    @DisplayName("enumerateServicesViaReflection decodes real service names from a gRPC-framed response")
    void testEnumerateServicesViaReflectionDecodesNames() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("http://example.com");

        byte[] response = buildListServicesResponse(
                "grpc.reflection.v1alpha.ServerReflection", "vulnerable.QueryService");

        when(httpClient.postBytesH2c(anyString(), anyMap(), any())).thenReturn(response);

        List<String> services = testCase.enumerateServicesViaReflection(endpoint, httpClient);

        assertEquals(2, services.size());
        assertTrue(services.contains("grpc.reflection.v1alpha.ServerReflection"));
        assertTrue(services.contains("vulnerable.QueryService"));
    }

    @Test
    @DisplayName("enumerateServicesViaReflection returns empty list for a malformed/truncated response")
    void testEnumerateServicesViaReflectionHandlesMalformedResponse() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/", "GET");
        endpoint.setBaseUrl("http://example.com");

        when(httpClient.postBytesH2c(anyString(), anyMap(), any())).thenReturn(new byte[]{0x01, 0x02});

        List<String> services = testCase.enumerateServicesViaReflection(endpoint, httpClient);

        assertTrue(services.isEmpty(), "Should return an empty list rather than throw for malformed data");
    }

    @Test
    @DisplayName("detectServerReflection includes enumerated service names in the finding evidence")
    void testDetectServerReflectionIncludesServiceNames() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "POST");

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString())).thenReturn(grpcResponse());
        when(httpClient.postBytesH2c(anyString(), anyMap(), any()))
                .thenReturn(buildListServicesResponse("vulnerable.QueryService"));

        List<Finding> findings = testCase.detectServerReflection(endpoint, httpClient);

        Finding reflectionFinding = findings.stream()
                .filter(f -> f.getTitle().equals("gRPC Server Reflection Enabled"))
                .findFirst().orElseThrow();
        assertTrue(reflectionFinding.getEvidence().contains("vulnerable.QueryService"),
                "Reflection finding evidence should list the enumerated service name");

        assertTrue(findings.stream().anyMatch(f ->
                        f.getTitle().contains("Suggests Data/Command Functionality")),
                "A service named 'QueryService' should be flagged for manual injection review");
    }

    @Test
    @DisplayName("detectServerReflection does not flag ordinary service names as interesting")
    void testDetectServerReflectionNoInterestingFindingForOrdinaryService() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", "POST");

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString())).thenReturn(grpcResponse());
        when(httpClient.postBytesH2c(anyString(), anyMap(), any()))
                .thenReturn(buildListServicesResponse("app.UserProfileService"));

        List<Finding> findings = testCase.detectServerReflection(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("Suggests Data/Command Functionality")),
                "An ordinary-sounding service name should not be flagged");
    }

    // ── execute (integration) ─────────────────────────────────────────────────

    @Test
    @DisplayName("execute returns both detection and reflection findings when both are present")
    void testExecuteBothFindingsPresent() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/grpc.health.v1.Health/Check", "POST");

        // All probes (detection + reflection) respond with gRPC content-type
        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
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

        when(httpClient.postH2c(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Network error"));

        assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient),
                "execute() should not propagate IOException");
    }
}
