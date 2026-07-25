package org.owasp.astf.testcases;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
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
 * Detection (+ reflection-based enumeration) stub for gRPC API endpoints.
 *
 * <p><strong>Why a stub?</strong> — Full gRPC security testing (calling arbitrary methods with
 * constructed request payloads) requires the target's Protobuf {@code .proto} schema files, or
 * a full decode of the reflection service's {@code FileDescriptorProto} responses, to know each
 * method's message shape. Building that generally would need a real protobuf/gRPC client library
 * (e.g. {@code grpc-java} + {@code protobuf-java}) that this project doesn't currently depend on
 * — adding it is future work, not attempted here.</p>
 *
 * <p>This test case therefore acts as a <em>detector + enumerator + advisor</em>:</p>
 * <ol>
 *   <li>It probes well-known gRPC paths for HTTP/2 + {@code application/grpc} signals.</li>
 *   <li>When a gRPC service is detected it emits an INFO finding that documents the recommended
 *       manual follow-up steps.</li>
 *   <li>It checks for the gRPC server reflection service, which — when enabled — lets attackers
 *       enumerate all RPC services without the .proto files (the gRPC equivalent of GraphQL
 *       introspection). When enabled, it attempts to go one step further than mere detection: it
 *       hand-encodes a minimal {@code ServerReflectionRequest{list_services}} protobuf message (a
 *       fixed 2-byte payload) and tries to decode the real service names from the response.</li>
 * </ol>
 *
 * <p><strong>Known limitation, confirmed by live testing (not just unit tests):</strong> the
 * {@code list_services} request/response encoding in {@link #enumerateServicesViaReflection} is
 * verified correct at the wire-protocol level — replaying the exact bytes this code sends via raw
 * {@code curl --http2-prior-knowledge} against a live gRPC Goat instance returns a valid, fully
 * decodable response — and the decode logic is covered by unit tests using that exact response
 * shape. But end-to-end, OkHttp's {@code Response.body()} for this call returns an immediately
 * {@code exhausted()} (empty) source against that same live target, despite the server having
 * sent real DATA frame bytes. This is a known category of issue: OkHttp is a general HTTP client,
 * not a gRPC client, and dedicated gRPC libraries like {@code grpc-java} implement substantial
 * custom stream-handling on top of raw HTTP/2 specifically to deal with gRPC's DATA/trailers
 * framing correctly — a plain synchronous {@code call().execute()} does not reliably work for
 * this bidi-streaming RPC. {@link #enumerateServicesViaReflection} therefore currently returns an
 * empty list against real gRPC servers in practice, even though the encode/decode logic itself is
 * correct; the "gRPC Server Reflection Enabled" detection finding (based on response headers, not
 * the body) is unaffected and still fires correctly. Fixing this for real would mean adopting a
 * proper gRPC transport (e.g. {@code grpc-java}'s OkHttp transport, or a raw HTTP/2 frame reader
 * bypassing OkHttp's higher-level abstraction) — flagged as follow-up work, not attempted here.</p>
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

    // Service-name keywords suggesting data/command-execution functionality worth prioritizing
    // for manual injection testing (SQL/OS command injection are common gRPC vulnerability
    // classes, e.g. gRPC Goat's dedicated SQL-injection and command-injection labs).
    private static final List<String> INTERESTING_SERVICE_KEYWORDS = List.of(
            "query", "sql", "exec", "command", "shell", "admin", "database", "db"
    );

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
                // lets us detect the service from the response headers alone. gRPC is
                // HTTP/2-only, so this must go over h2c prior-knowledge for cleartext
                // targets — a plain HTTP/1.1 request cannot connect to a gRPC server at all.
                HttpResponse response = httpClient.postH2c(
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
            HttpResponse response = httpClient.postH2c(
                    url,
                    Map.of("Content-Type", GRPC_CONTENT_TYPE, "TE", "trailers"),
                    GRPC_CONTENT_TYPE,
                    ""
            );

            if (response != null && isGrpcResponse(response)) {
                // Reflection service responded — it is active. Go beyond mere detection: try to
                // actually enumerate the real service names via a hand-encoded list_services call.
                List<String> services = enumerateServicesViaReflection(endpoint, httpClient);

                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "gRPC Server Reflection Enabled",
                        "The gRPC server reflection service is active. This allows any client to " +
                        "enumerate all RPC methods and their message types without the .proto files, " +
                        "greatly simplifying targeted attacks against the service." +
                        (services.isEmpty() ? "" : " Enumerated " + services.size() +
                                " service(s): " + String.join(", ", services)),
                        Severity.MEDIUM,
                        getId(),
                        "POST " + REFLECTION_PATH,
                        "Disable the gRPC reflection service in production. In Go (grpc-go), " +
                        "remove 'reflection.Register(s)'. In Java, remove " +
                        "'ProtoReflectionService.newInstance()' from the server builder. " +
                        "Only enable reflection in development/staging environments."
                );
                f.setEvidence("gRPC reflection service at " + url +
                        " returned content-type: application/grpc" +
                        (services.isEmpty() ? "" : "; services: " + String.join(", ", services)));
                findings.add(f);

                findings.addAll(buildInterestingServiceFindings(endpoint, services));
            }
        } catch (Exception e) {
            logger.debug("gRPC reflection not detected at {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    /**
     * Flags reflection-enumerated services whose name suggests data/command-execution
     * functionality — common targets for gRPC's own SQL/command-injection vulnerability classes —
     * as worth prioritizing for manual injection testing (which this framework can't automate
     * without the target's .proto schema; see the class-level Javadoc).
     */
    private List<Finding> buildInterestingServiceFindings(EndpointInfo endpoint, List<String> services) {
        List<Finding> findings = new ArrayList<>();
        for (String service : services) {
            String lowerService = service.toLowerCase();
            boolean interesting = INTERESTING_SERVICE_KEYWORDS.stream().anyMatch(lowerService::contains);
            if (interesting) {
                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "gRPC Service Name Suggests Data/Command Functionality — Review Manually",
                        String.format("The reflection-enumerated service '%s' has a name suggesting " +
                                "it executes queries or commands — a common target for gRPC's own " +
                                "SQL-injection and command-injection vulnerability classes. This " +
                                "framework cannot automatically construct valid requests for it " +
                                "without the target's .proto schema; manual testing with grpcurl " +
                                "(using the discovered reflection service) is recommended.",
                                service),
                        Severity.INFO,
                        getId(),
                        "POST " + REFLECTION_PATH,
                        "Manually enumerate this service's methods with grpcurl (which supports " +
                        "server reflection) and test each string-typed argument with SQL/command " +
                        "injection payloads, verifying parameterized queries and no shell " +
                        "invocation with unsanitized input."
                );
                f.setEvidence("Service discovered via reflection: " + service);
                findings.add(f);
            }
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

    // ── gRPC reflection: minimal hand-rolled protobuf encode/decode ──────────
    //
    // Deliberately narrow: only handles the one fixed request shape this test case needs
    // (ServerReflectionRequest{list_services: ""}) and the one fixed response shape it reads
    // back (ServerReflectionResponse -> ListServiceResponse -> repeated ServiceResponse{name}).
    // This is NOT a general-purpose protobuf library — building one would duplicate
    // protobuf-java, which is exactly the dependency this test case's class-level Javadoc
    // explains ASTF doesn't take on for full gRPC support.

    /**
     * Calls the gRPC reflection service's {@code list_services} operation and returns the real
     * service names discovered, or an empty list if reflection didn't respond in the expected
     * shape (including when it's simply not enabled, or the target isn't gRPC at all).
     */
    List<String> enumerateServicesViaReflection(EndpointInfo endpoint, HttpClient httpClient) {
        String baseUrl = endpoint.getBaseUrl() != null ? endpoint.getBaseUrl() : "";
        String url = baseUrl + REFLECTION_PATH;
        try {
            byte[] responseFrame = httpClient.postBytesH2c(
                    url,
                    Map.of("Content-Type", GRPC_CONTENT_TYPE, "TE", "trailers"),
                    encodeListServicesRequest());

            byte[] responseMessage = unwrapGrpcFrame(responseFrame);
            if (responseMessage == null) {
                return List.of();
            }
            // ServerReflectionResponse.list_services_response is field 6
            List<byte[]> listServicesResponses = extractLengthDelimitedFields(responseMessage, 6);
            if (listServicesResponses.isEmpty()) {
                return List.of();
            }
            // ListServiceResponse.service is repeated field 1
            List<byte[]> serviceEntries = extractLengthDelimitedFields(listServicesResponses.get(0), 1);

            List<String> names = new ArrayList<>();
            for (byte[] entry : serviceEntries) {
                // ServiceResponse.name is field 1
                List<byte[]> nameField = extractLengthDelimitedFields(entry, 1);
                if (!nameField.isEmpty()) {
                    names.add(new String(nameField.get(0), StandardCharsets.UTF_8));
                }
            }
            return names;
        } catch (Exception e) {
            logger.debug("Error enumerating gRPC services via reflection on {}: {}", endpoint, e.getMessage());
            return List.of();
        }
    }

    /**
     * Encodes {@code ServerReflectionRequest{list_services: ""}} (field 7, wire type 2,
     * zero-length string) wrapped in a gRPC frame. This is a fixed 7-byte payload:
     * 5-byte gRPC frame header + 2-byte protobuf field (tag 0x3A, length 0).
     */
    byte[] encodeListServicesRequest() {
        byte[] message = { 0x3A, 0x00 }; // field 7 << 3 | wiretype 2 = 0x3A; length 0
        return wrapGrpcFrame(message);
    }

    /** Prepends the 5-byte gRPC frame header (1-byte compression flag + 4-byte big-endian length). */
    private byte[] wrapGrpcFrame(byte[] message) {
        ByteBuffer buffer = ByteBuffer.allocate(5 + message.length);
        buffer.put((byte) 0); // uncompressed
        buffer.putInt(message.length);
        buffer.put(message);
        return buffer.array();
    }

    /** Strips the 5-byte gRPC frame header, returning the raw protobuf message bytes. */
    private byte[] unwrapGrpcFrame(byte[] framed) {
        if (framed == null || framed.length < 5) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(framed);
        buffer.get(); // compression flag, ignored
        int length = buffer.getInt();
        if (length < 0 || 5 + length > framed.length) {
            return null; // truncated or malformed frame
        }
        byte[] message = new byte[length];
        buffer.get(message);
        return message;
    }

    /**
     * Walks a protobuf message's top-level fields and returns the raw bytes of every
     * length-delimited (wire type 2) field matching {@code targetFieldNumber} — used both for
     * message fields (nested messages) and string/bytes scalar fields, which share wire type 2.
     */
    private List<byte[]> extractLengthDelimitedFields(byte[] data, int targetFieldNumber) {
        List<byte[]> results = new ArrayList<>();
        int index = 0;
        while (index < data.length) {
            long[] tagResult = readVarint(data, index);
            long tag = tagResult[0];
            index = (int) tagResult[1];
            int fieldNumber = (int) (tag >>> 3);
            int wireType = (int) (tag & 0x7);

            switch (wireType) {
                case 0 -> { // varint — read and discard
                    long[] v = readVarint(data, index);
                    index = (int) v[1];
                }
                case 1 -> index += 8;  // fixed64
                case 5 -> index += 4;  // fixed32
                case 2 -> {            // length-delimited
                    long[] lenResult = readVarint(data, index);
                    int len = (int) lenResult[0];
                    index = (int) lenResult[1];
                    if (index + len > data.length) {
                        return results; // malformed/truncated — return what we have so far
                    }
                    if (fieldNumber == targetFieldNumber) {
                        results.add(Arrays.copyOfRange(data, index, index + len));
                    }
                    index += len;
                }
                default -> {
                    return results; // unsupported/deprecated wire type (e.g. groups) — stop
                }
            }
        }
        return results;
    }

    /**
     * Reads a protobuf-style base-128 varint starting at {@code index}.
     *
     * @return a 2-element array: {@code [value, nextIndex]}
     */
    private long[] readVarint(byte[] data, int index) {
        long result = 0;
        int shift = 0;
        while (index < data.length) {
            byte b = data[index++];
            result |= ((long) (b & 0x7F)) << shift;
            if ((b & 0x80) == 0) {
                return new long[]{result, index};
            }
            shift += 7;
            if (shift > 63) {
                throw new IllegalArgumentException("Varint too long");
            }
        }
        throw new IllegalArgumentException("Truncated varint");
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
