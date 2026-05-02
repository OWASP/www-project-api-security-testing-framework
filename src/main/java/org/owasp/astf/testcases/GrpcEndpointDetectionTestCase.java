package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

/**
 * Detection stub for gRPC API endpoints.
 *
 * <p><strong>Why a stub?</strong> — Full gRPC security testing requires the
 * target's Protobuf {@code .proto} schema files to generate typed client stubs.
 * Without those files it is impossible to construct valid RPC payloads, making
 * automated exploit testing impractical in a generic framework.</p>
 *
 * <p>This test case therefore acts as a <em>detector + advisor</em>:</p>
 * <ol>
 *   <li>It probes well-known gRPC paths for HTTP/2 + {@code application/grpc}
 *       signals.</li>
 *   <li>When a gRPC service is detected it emits an INFO finding that documents
 *       the recommended manual follow-up steps.</li>
 *   <li>It checks for the gRPC server reflection service, which — when enabled —
 *       lets attackers enumerate all RPC methods without the .proto files (the
 *       gRPC equivalent of GraphQL introspection).</li>
 * </ol>
 *
 * <p>Test case ID: {@code ASTF-GRPC-2023}</p>
 */
public class GrpcEndpointDetectionTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(GrpcEndpointDetectionTestCase.class);

    static final String TEST_CASE_ID = "ASTF-GRPC-2023";

    // Standard gRPC health check path (grpc.health.v1.Health/Check)
    private static final String HEALTH_CHECK_PATH = "/grpc.health.v1.Health/Check";

    // gRPC server reflection service path (ServerReflection/ServerReflectionInfo)
    private static final String REFLECTION_PATH =
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

    // Common gRPC service paths to probe
    private static final List<String> GRPC_PROBE_PATHS = List.of(
            HEALTH_CHECK_PATH,
            "/grpc.health.v1.Health/Watch",
            REFLECTION_PATH
    );

    // gRPC uses application/grpc as the content type
    private static final String GRPC_CONTENT_TYPE = "application/grpc";

    @Override
    public String getId() {
        return TEST_CASE_ID;
    }

    @Override
    public String getName() {
        return "gRPC Endpoint Detection";
    }

    @Override
    public String getDescription() {
        return "Detects gRPC API endpoints by probing for HTTP/2 + application/grpc signals " +
               "and checks for server reflection (schema enumeration) being enabled. " +
               "Full gRPC security testing requires .proto schema files and must be performed manually.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(detectGrpcEndpoint(endpoint, httpClient));
        findings.addAll(detectServerReflection(endpoint, httpClient));

        return findings;
    }

    // ── Detection: is this a gRPC endpoint? ──────────────────────────────────

    /**
     * Probes known gRPC paths.  A response with {@code content-type: application/grpc}
     * (or its variants like {@code application/grpc+proto}) is a reliable indicator
     * of a gRPC service even when the HTTP status code is non-2xx.
     */
    List<Finding> detectGrpcEndpoint(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = endpoint.getBaseUrl() != null ? endpoint.getBaseUrl() : "";

        for (String path : GRPC_PROBE_PATHS) {
            try {
                String url = baseUrl + path;
                // gRPC frames are binary, but an HTTP POST with the gRPC content-type
                // lets us detect the service from the response headers alone.
                HttpResponse response = httpClient.postWithStatus(
                        url,
                        Map.of("Content-Type", GRPC_CONTENT_TYPE, "TE", "trailers"),
                        GRPC_CONTENT_TYPE,
                        ""  // empty body — we are probing, not sending a valid frame
                );

                if (response != null && isGrpcResponse(response)) {
                    logger.info("gRPC endpoint detected at: {}", url);
                    findings.add(buildGrpcDetectedFinding(endpoint, path));
                    break; // one detection finding is sufficient
                }
            } catch (Exception e) {
                logger.debug("No gRPC response at {}: {}", path, e.getMessage());
            }
        }
        return findings;
    }

    /**
     * Checks for the gRPC server reflection service.  When enabled, it lets any
     * client list all available RPC methods — the equivalent of GraphQL introspection.
     */
    List<Finding> detectServerReflection(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = endpoint.getBaseUrl() != null ? endpoint.getBaseUrl() : "";

        try {
            String url = baseUrl + REFLECTION_PATH;
            HttpResponse response = httpClient.postWithStatus(
                    url,
                    Map.of("Content-Type", GRPC_CONTENT_TYPE, "TE", "trailers"),
                    GRPC_CONTENT_TYPE,
                    ""
            );

            if (response != null && isGrpcResponse(response)) {
                // Reflection service responded — it is active
                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "gRPC Server Reflection Enabled",
                        "The gRPC server reflection service is active. This allows any client to " +
                        "enumerate all RPC methods and their message types without the .proto files, " +
                        "greatly simplifying targeted attacks against the service.",
                        Severity.MEDIUM,
                        getId(),
                        "POST " + REFLECTION_PATH,
                        "Disable the gRPC reflection service in production. In Go (grpc-go), " +
                        "remove 'reflection.Register(s)'. In Java, remove " +
                        "'ProtoReflectionService.newInstance()' from the server builder. " +
                        "Only enable reflection in development/staging environments."
                );
                f.setEvidence("gRPC reflection service at " + url +
                        " returned content-type: application/grpc");
                findings.add(f);
            }
        } catch (Exception e) {
            logger.debug("gRPC reflection not detected at {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Returns {@code true} when a response has a {@code content-type} header
     * that starts with {@code application/grpc}, which is the canonical signal
     * of a gRPC service regardless of the HTTP status code.
     */
    boolean isGrpcResponse(HttpResponse response) {
        Map<String, List<String>> headers = response.getHeaders();
        if (headers == null) return false;

        return headers.entrySet().stream()
                .filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("content-type"))
                .flatMap(e -> e.getValue().stream())
                .anyMatch(v -> v != null && v.toLowerCase().startsWith("application/grpc"));
    }

    private Finding buildGrpcDetectedFinding(EndpointInfo endpoint, String detectedPath) {
        return new Finding(
                UUID.randomUUID().toString(),
                "gRPC Endpoint Detected — Manual Security Review Required",
                "A gRPC endpoint was detected. Automated security testing of gRPC services " +
                "requires the .proto schema files to construct valid RPC payloads. " +
                "The following manual tests are recommended:\n" +
                "  • Authentication: verify all methods require valid credentials\n" +
                "  • Authorization: test BOLA/BFLA by calling methods with a lower-privilege token\n" +
                "  • Input validation: send malformed/oversized Protobuf messages\n" +
                "  • Rate limiting: verify server-side streaming methods cannot be abused\n" +
                "  • TLS: confirm all endpoints enforce mutual TLS or at minimum server-side TLS\n" +
                "  • Error handling: ensure gRPC status codes don't leak stack traces",
                Severity.INFO,
                getId(),
                "POST " + detectedPath,
                "Use specialised tools such as grpcurl, ghz, or Postman (gRPC support) " +
                "together with your .proto files to perform comprehensive gRPC security testing. " +
                "Consider integrating grpc-dumper or a gRPC proxy (e.g. Envoy) for traffic analysis."
        );
    }
}
