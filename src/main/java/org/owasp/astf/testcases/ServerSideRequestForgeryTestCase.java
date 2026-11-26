package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Tests for API7:2023 Server Side Request Forgery (SSRF).
 *
 * SSRF vulnerabilities occur when an API fetches a remote resource using a user-supplied URL
 * without validating it. Attackers can trick the server into fetching internal resources,
 * cloud metadata endpoints, or other internal services.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/">OWASP API7:2023</a>
 */
public class ServerSideRequestForgeryTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(ServerSideRequestForgeryTestCase.class);

    // URL parameters commonly used to pass URLs to the server
    private static final List<String> URL_PARAMETERS = List.of(
            "url", "uri", "link", "src", "source", "target", "dest", "destination",
            "redirect", "return", "returnUrl", "return_url", "callback", "callbackUrl",
            "webhook", "webhookUrl", "webhook_url", "fetch", "load", "path",
            "imageUrl", "image_url", "avatar", "icon", "file", "document"
    );

    // SSRF test payloads targeting cloud metadata and internal services
    private static final List<String> SSRF_PAYLOADS = List.of(
            "http://169.254.169.254/latest/meta-data/",          // AWS metadata
            "http://metadata.google.internal/computeMetadata/",   // GCP metadata
            "http://169.254.169.254/metadata/instance",           // Azure metadata
            "http://localhost/",                                   // localhost
            "http://127.0.0.1/",                                  // loopback
            "http://[::1]/",                                       // IPv6 loopback
            "http://0.0.0.0/"                                      // any interface
    );

    // Content patterns that indicate successful SSRF (returned from metadata endpoints)
    private static final List<String> SSRF_INDICATORS = List.of(
            "ami-id", "instance-id", "instance-type",             // AWS metadata keys
            "computeMetadata", "serviceAccounts",                   // GCP metadata keys
            "subscriptionId", "resourceGroupName",                  // Azure metadata keys
            "root:x:", "www-data",                                  // /etc/passwd content
            "docker", "kubernetes", "k8s"                          // container environment
    );
    // GCP/Azure metadata endpoints require a dedicated header; an error naming that header
    // proves the server reached the metadata service even though the fetch itself failed.
    private static final List<String> METADATA_HEADER_REQUIRED_INDICATORS = List.of(
            "missing metadata-flavor: google header",
            "missing metadata-flavor:google header",
            "required metadata header not specified"
    );

    // Field names treated as URL-shaped when substituting into a discovered JSON body
    private static final Set<String> URL_SHAPED_FIELD_NAMES = Set.of(
            "url", "uri", "link", "href", "callback", "webhook", "endpoint", "target",
            "image", "avatar", "src", "feed", "redirect", "host"
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getId() {
        return "ASTF-API7-2023";
    }

    @Override
    public String getName() {
        return "Server Side Request Forgery";
    }

    @Override
    public String getDescription() {
        return "Tests for SSRF vulnerabilities by injecting internal or cloud metadata URLs into " +
               "parameters that the API may use to fetch remote resources.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testQueryParameterSsrf(endpoint, httpClient));
        findings.addAll(testBodyParameterSsrf(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testQueryParameterSsrf(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        String baseUrl = endpoint.getFullUrl();
        String baselineBody = fetchBaselineBody(endpoint, httpClient);
        Set<String> baselineIndicators = indicatorsIn(baselineBody);

        for (String param : URL_PARAMETERS) {
            for (String payload : SSRF_PAYLOADS) {
                String testUrl = baseUrl + (baseUrl.contains("?") ? "&" : "?") +
                        param + "=" + urlEncode(payload);
                try {
                    HttpResponse response = httpClient.getWithStatus(testUrl, Map.of());
                    if (response == null) {
                        continue;
                    }

                    String metaIndicator = newMetadataHeaderIndicator(
                            response.getBody(), payload, baselineBody, baselineIndicators);
                    if (metaIndicator != null) {
                        String freshBaseline = fetchBaselineBody(endpoint, httpClient);
                        if (freshBaseline.toLowerCase(Locale.ROOT)
                                .contains(metaIndicator.toLowerCase(Locale.ROOT))) {
                            logger.debug("Metadata-header indicator '{}' on {} also appears in a fresh baseline, not reporting",
                                    metaIndicator, endpoint);
                            baselineBody = freshBaseline;
                            baselineIndicators = indicatorsIn(freshBaseline);
                            continue;
                        }
                        findings.add(buildMetadataHeaderFinding(
                                endpoint, "query", param, payload, "GET " + testUrl, metaIndicator));
                        return findings;
                    }

                    String indicator = newSsrfIndicator(
                            response.getBody(), payload, baselineBody, baselineIndicators);
                    if (indicator != null) {
                        // Content can change during a scan (another check posts data that the endpoint
                        // then lists). If the endpoint's normal response now contains the same
                        // indicator, it is not attributable to the payload: refresh the baseline and
                        // keep testing.
                        String freshBaseline = fetchBaselineBody(endpoint, httpClient);
                        if (freshBaseline.toLowerCase(Locale.ROOT)
                                .contains(indicator.toLowerCase(Locale.ROOT))) {
                            logger.debug("SSRF indicator '{}' on {} also appears in a fresh baseline, not reporting",
                                    indicator, endpoint);
                            baselineBody = freshBaseline;
                            baselineIndicators = indicatorsIn(freshBaseline);
                            continue;
                        }
                        // A non-2xx body with new metadata content is usually a validation error that
                        // mentions an indicator word, but a proxy that relays the upstream status can
                        // also return real metadata with a 4xx/5xx. Report it as possible, not drop it.
                        boolean confirmed = response.isSuccess();
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                confirmed ? "Server Side Request Forgery (SSRF) via Query Parameter"
                                        : "Possible Server Side Request Forgery (SSRF) via Query Parameter (non-2xx response)",
                                String.format("The API parameter '%s' appears to be vulnerable to SSRF. " +
                                        "The server fetched the URL '%s' and returned content that matches " +
                                        "known internal/metadata service response patterns.",
                                        param, payload),
                                confirmed ? Severity.CRITICAL : Severity.MEDIUM,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Validate and sanitize all user-supplied URLs. Use an allowlist of permitted " +
                                "domains/IPs. Block requests to private IP ranges (RFC 1918) and cloud metadata " +
                                "endpoints. Disable unnecessary URL-fetching functionality."
                        );
                        finding.setRequestDetails("GET " + testUrl);
                        finding.setEvidence("Response contained '" + indicator + "', which is not part of the payload " +
                                "and not in the endpoint's normal response (checked again before reporting). Payload: " + payload);
                        findings.add(finding);
                        return findings; // One confirmed SSRF is enough
                    }
                } catch (Exception e) {
                    logger.debug("Error testing SSRF param {} on {}: {}", param, endpoint, e.getMessage());
                }
            }
        }

        return findings;
    }

    private List<Finding> testBodyParameterSsrf(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String method = endpoint.getMethod().toUpperCase(Locale.ROOT);

        if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH")) {
            return findings;
        }

        String baselineBody = fetchBaselineBody(endpoint, httpClient);
        Set<String> baselineIndicators = indicatorsIn(baselineBody);

        ObjectNode discoveredBody = parseDiscoveredObjectBody(endpoint);
        if (discoveredBody != null && hasUrlShapedField(discoveredBody)) {
            for (String payload : SSRF_PAYLOADS) {
                String body = buildBodyKeepingFields(discoveredBody, payload);
                BodyProbeOutcome outcome = probeBody(endpoint, httpClient, method, body, payload,
                        "url-shaped fields", baselineBody, baselineIndicators);
                if (outcome.freshBaseline() != null) {
                    baselineBody = outcome.freshBaseline();
                    baselineIndicators = indicatorsIn(baselineBody);
                    continue;
                }
                if (outcome.finding() != null) {
                    findings.add(outcome.finding());
                    return findings;
                }
            }
            // Deliberately no return here: a body that has one URL-shaped field can still be
            // vulnerable through a different parameter the discovered body does not list (2.0.2
            // tried every name in URL_PARAMETERS). Falling through keeps that coverage; the probes
            // below keep the discovered fields, so they still get past required-field validation.
        }

        // Try each URL_PARAMETERS name, added alongside the discovered fields (or alone when there
        // is no discovered body, as in 2.0.2).
        ObjectNode template = discoveredBody != null ? discoveredBody : objectMapper.createObjectNode();
        for (String param : URL_PARAMETERS) {
            for (String payload : SSRF_PAYLOADS) {
                String body = buildBodyWithField(template, param, payload);
                BodyProbeOutcome outcome = probeBody(endpoint, httpClient, method, body, payload,
                        param, baselineBody, baselineIndicators);
                if (outcome.freshBaseline() != null) {
                    baselineBody = outcome.freshBaseline();
                    baselineIndicators = indicatorsIn(baselineBody);
                    continue;
                }
                if (outcome.finding() != null) {
                    findings.add(outcome.finding());
                    return findings;
                }
            }
        }

        return findings;
    }

    private record BodyProbeOutcome(Finding finding, String freshBaseline) {
        static BodyProbeOutcome none() { return new BodyProbeOutcome(null, null); }
        static BodyProbeOutcome report(Finding f) { return new BodyProbeOutcome(f, null); }
        static BodyProbeOutcome refresh(String baseline) { return new BodyProbeOutcome(null, baseline); }
    }

    private BodyProbeOutcome probeBody(EndpointInfo endpoint, HttpClient httpClient, String method,
                                       String body, String payload, String paramLabel,
                                       String baselineBody, Set<String> baselineIndicators) {
        try {
            HttpResponse response = switch (method) {
                case "POST"  -> httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                case "PUT"   -> httpClient.putWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                case "PATCH" -> httpClient.patchWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                default      -> null;
            };
            if (response == null) {
                return BodyProbeOutcome.none();
            }

            String requestDetails = method + " " + endpoint.getFullUrl() + "\nBody: " + body;

            String metaIndicator = newMetadataHeaderIndicator(
                    response.getBody(), payload, baselineBody, baselineIndicators);
            if (metaIndicator != null) {
                String freshBaseline = fetchBaselineBody(endpoint, httpClient);
                if (freshBaseline.toLowerCase(Locale.ROOT)
                        .contains(metaIndicator.toLowerCase(Locale.ROOT))) {
                    logger.debug("Metadata-header indicator '{}' on {} also appears in a fresh baseline, not reporting",
                            metaIndicator, endpoint);
                    return BodyProbeOutcome.refresh(freshBaseline);
                }
                return BodyProbeOutcome.report(buildMetadataHeaderFinding(
                        endpoint, "body", paramLabel, payload, requestDetails, metaIndicator));
            }

            String indicator = newSsrfIndicator(
                    response.getBody(), payload, baselineBody, baselineIndicators);
            if (indicator != null) {
                String freshBaseline = fetchBaselineBody(endpoint, httpClient);
                if (freshBaseline.toLowerCase(Locale.ROOT)
                        .contains(indicator.toLowerCase(Locale.ROOT))) {
                    logger.debug("SSRF indicator '{}' on {} also appears in a fresh baseline, not reporting",
                            indicator, endpoint);
                    return BodyProbeOutcome.refresh(freshBaseline);
                }
                boolean confirmed = response.isSuccess();
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        confirmed ? "Server Side Request Forgery (SSRF) via Request Body"
                                : "Possible Server Side Request Forgery (SSRF) via Request Body (non-2xx response)",
                        String.format("The API body parameter '%s' appears to be vulnerable to SSRF. " +
                                "The server fetched the URL '%s' and returned content that matches " +
                                "known internal/metadata service response patterns.",
                                paramLabel, payload),
                        confirmed ? Severity.CRITICAL : Severity.MEDIUM,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Validate and sanitize all user-supplied URLs in request bodies. " +
                        "Use a URL allowlist and block requests to internal network ranges."
                );
                finding.setRequestDetails(requestDetails);
                finding.setEvidence("Response contained '" + indicator + "', which is not part of the payload " +
                        "and not in the endpoint's normal response (checked again before reporting). Payload: " + payload);
                return BodyProbeOutcome.report(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing body SSRF on {}: {}", endpoint, e.getMessage());
        }
        return BodyProbeOutcome.none();
    }

    private Finding buildMetadataHeaderFinding(EndpointInfo endpoint, String via, String param,
                                               String payload, String requestDetails, String indicator) {
        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                "Server Side Request Forgery (metadata service reached, header required)",
                String.format("The API %s parameter '%s' caused the server to reach a cloud metadata " +
                        "endpoint at '%s'. The metadata service responded that a required header is missing, " +
                        "which proves the outbound fetch happened.",
                        via, param, payload),
                Severity.HIGH,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Validate and sanitize all user-supplied URLs. Use an allowlist of permitted " +
                "domains/IPs. Block requests to private IP ranges (RFC 1918) and cloud metadata " +
                "endpoints. Disable unnecessary URL-fetching functionality."
        );
        finding.setRequestDetails(requestDetails);
        finding.setEvidence("Response contained '" + indicator + "' (metadata header required), which is not " +
                "part of the payload and not in the endpoint's normal response. Payload: " + payload);
        return finding;
    }

    /**
     * Returns a deep copy of the endpoint's discovered JSON object body, or null when none is
     * usable — callers then fall back to the historical single-field {@code {"url":...}} probes.
     */
    private ObjectNode parseDiscoveredObjectBody(EndpointInfo endpoint) {
        String discovered = endpoint.getRequestBody();
        if (discovered == null || discovered.isBlank()) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(discovered);
            if (root.isObject() && root.size() > 0) {
                return (ObjectNode) root.deepCopy();
            }
        } catch (Exception e) {
            logger.debug("Discovered request body for {} isn't a JSON object: {}", endpoint, e.getMessage());
        }
        return null;
    }

    /**
     * Keeps every field from the discovered body and substitutes the SSRF payload into its
     * URL-shaped fields (by name or http(s) string value).
     */
    private String buildBodyKeepingFields(ObjectNode template, String payload) {
        ObjectNode copy = template.deepCopy();
        for (String key : urlShapedFields(copy)) {
            copy.put(key, payload);
        }
        return writeJson(copy, "url", payload);
    }

    /** Keeps every field from {@code template} and sets {@code param} to the payload. */
    private String buildBodyWithField(ObjectNode template, String param, String payload) {
        ObjectNode copy = template.deepCopy();
        copy.put(param, payload);
        return writeJson(copy, param, payload);
    }

    private boolean hasUrlShapedField(ObjectNode body) {
        return !urlShapedFields(body).isEmpty();
    }

    private List<String> urlShapedFields(ObjectNode body) {
        List<String> names = new ArrayList<>();
        Iterator<Map.Entry<String, JsonNode>> fields = body.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            if (isUrlShapedField(entry.getKey()) || looksLikeHttpUrl(entry.getValue())) {
                names.add(entry.getKey());
            }
        }
        return names;
    }

    private String writeJson(ObjectNode body, String fallbackField, String payload) {
        try {
            return objectMapper.writeValueAsString(body);
        } catch (Exception e) {
            return String.format("{\"%s\":\"%s\"}", fallbackField, payload);
        }
    }

    /**
     * True when a whole word of the field name is a URL-shaped word: {@code imageUrl},
     * {@code webhook_url}, {@code callback-uri} and {@code feed} qualify. Matching words rather
     * than substrings matters: {@code "uri"} is inside {@code "security"} and {@code "during"}, and
     * {@code "host"} is inside {@code "ghost"}, so a substring match would overwrite ordinary
     * fields with the SSRF payload and send a body the server rejects for the wrong reason.
     */
    private boolean isUrlShapedField(String name) {
        String spaced = name.replaceAll("([a-z0-9])([A-Z])", "$1 $2")   // imageUrl -> image Url
                .replaceAll("[^A-Za-z0-9]+", " ")                       // webhook_url -> webhook url
                .toLowerCase(Locale.ROOT)
                .trim();
        return Stream.of(spaced.split(" ")).anyMatch(URL_SHAPED_FIELD_NAMES::contains);
    }

    private boolean looksLikeHttpUrl(JsonNode value) {
        if (value == null || !value.isTextual()) {
            return false;
        }
        String text = value.asText().toLowerCase(Locale.ROOT);
        return text.startsWith("http://") || text.startsWith("https://");
    }

    /**
     * Fetches the endpoint's normal (un-injected) response body. Some indicators (notably the
     * generic environment words "docker"/"kubernetes"/"k8s") can legitimately appear in an API's
     * ordinary response; without this baseline every probe against such an endpoint would be a
     * false positive.
     */
    private String fetchBaselineBody(EndpointInfo endpoint, HttpClient httpClient) {
        try {
            HttpResponse baseline = httpClient.getWithStatus(endpoint.getFullUrl(), Map.of());
            return baseline == null || baseline.getBody() == null ? "" : baseline.getBody();
        } catch (Exception e) {
            logger.debug("Error fetching SSRF baseline for {}: {}", endpoint, e.getMessage());
            return "";
        }
    }

    private Set<String> indicatorsIn(String body) {
        String lower = body.toLowerCase(Locale.ROOT);
        return Stream.concat(SSRF_INDICATORS.stream(), METADATA_HEADER_REQUIRED_INDICATORS.stream())
                .filter(indicator -> lower.contains(indicator.toLowerCase(Locale.ROOT)))
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Returns the first SSRF indicator in the response that is attributable to the
     * injected payload actually being fetched. The payload itself can contain an indicator
     * (e.g. "computeMetadata"), so an API that merely echoes its input would reproduce it; the
     * payload text is therefore removed before matching. An indicator already present in the
     * baseline response, or a body identical to the baseline, is not evidence either.
     */
    private String newSsrfIndicator(String body, String payload, String baselineBody,
                                    Set<String> baselineIndicators) {
        if (body == null || body.isEmpty()) return null;
        if (body.equals(baselineBody)) return null;
        String lower = stripPayloadEchoes(body, payload).toLowerCase(Locale.ROOT);
        return SSRF_INDICATORS.stream()
                .filter(indicator -> !baselineIndicators.contains(indicator))
                .filter(indicator -> lower.contains(indicator.toLowerCase(Locale.ROOT)))
                .findFirst()
                .orElse(null);
    }

    private String newMetadataHeaderIndicator(String body, String payload, String baselineBody,
                                              Set<String> baselineIndicators) {
        if (body == null || body.isEmpty()) return null;
        if (body.equals(baselineBody)) return null;
        String lower = stripPayloadEchoes(body, payload).toLowerCase(Locale.ROOT);
        return METADATA_HEADER_REQUIRED_INDICATORS.stream()
                .filter(indicator -> !baselineIndicators.contains(indicator))
                .filter(indicator -> lower.contains(indicator.toLowerCase(Locale.ROOT)))
                .findFirst()
                .orElse(null);
    }

    /** Removes the payload from the body in its raw, URL-encoded, JSON-escaped and scheme-less forms. */
    private String stripPayloadEchoes(String body, String payload) {
        String schemeLess = payload.replaceFirst("^[a-zA-Z]+://", "");
        List<String> echoes = new ArrayList<>();
        for (String form : List.of(payload, schemeLess)) {
            echoes.add(form);
            echoes.add(form.replace("/", "\\/"));
            echoes.add(urlEncode(form));
            echoes.add(java.net.URLEncoder.encode(form, java.nio.charset.StandardCharsets.UTF_8));
        }
        String result = body;
        // Longest first so a scheme-less form never leaves a partial remainder of a longer one
        for (String echo : echoes.stream().sorted((x, y) -> y.length() - x.length()).toList()) {
            result = result.replace(echo, "");
        }
        return result;
    }

    private String urlEncode(String value) {
        return value.replace(":", "%3A").replace("/", "%2F").replace("?", "%3F")
                .replace("=", "%3D").replace("&", "%26").replace(" ", "%20");
    }
}
