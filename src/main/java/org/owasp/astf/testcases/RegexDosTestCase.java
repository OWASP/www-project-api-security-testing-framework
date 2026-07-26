package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Tests REST endpoint body fields for ReDoS (Regular Expression Denial of Service) —
 * catastrophic-backtracking input that causes a vulnerable validation regex to hang the server.
 *
 * <p>Found by tracing ASTF's actual findings against VAmPI's own documented vulnerability list:
 * VAmPI documents a ReDoS vulnerability on its email-update endpoint, and no test case in this
 * framework attempted it at all.</p>
 *
 * <p>Test case ID: {@code ASTF-REDOS-2023} — like injection, ReDoS doesn't map to a single
 * numbered OWASP API Security Top 10 (2023) category, so this follows the same convention
 * already used for GraphQL/gRPC/mTLS/LLM/Injection.</p>
 */
public class RegexDosTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(RegexDosTestCase.class);

    // Fields most commonly validated with a (potentially vulnerable) format-checking regex.
    private static final List<String> TARGET_FIELD_NAMES = List.of("email", "phone", "url", "username", "name");

    // Generic catastrophic-backtracking triggers: a long run of a repeated character followed by
    // one that can't match, designed to hit common vulnerable patterns with nested/overlapping
    // quantifiers (e.g. (a+)+$, (a|a)+$, (a|aa)+$) without needing to know the target's exact
    // regex. 35 repetitions is enough to make an O(2^n) blowup take seconds, not guessed at
    // random — it's the same order of magnitude used in VAmPI's own documented ReDoS payload.
    private static final List<String> REDOS_PAYLOADS = List.of(
            "a".repeat(35) + "!",
            "a".repeat(35) + "@",
            "1".repeat(35) + "!"
    );

    private static final long ABSOLUTE_SLOW_THRESHOLD_MS = 4000;
    private static final long BASELINE_MULTIPLIER = 8;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getId() {
        return "ASTF-REDOS-2023";
    }

    @Override
    public String getName() {
        return "Regular Expression Denial of Service (ReDoS)";
    }

    @Override
    public String getDescription() {
        return "Tests REST endpoint body fields for catastrophic-backtracking regex " +
               "vulnerabilities by measuring response latency for known ReDoS-triggering input.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        List<Finding> findings = new ArrayList<>();
        String method = endpoint.getMethod().toUpperCase();
        if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH")) {
            return findings;
        }

        logger.info("Executing {} test on {}", getId(), endpoint);

        List<String> fields = extractBodyFieldNames(endpoint);

        long baselineElapsed;
        try {
            long start = System.currentTimeMillis();
            sendRequest(endpoint, httpClient, buildJsonBody(fields, null, null));
            baselineElapsed = System.currentTimeMillis() - start;
        } catch (Exception e) {
            logger.debug("Could not establish a baseline response time for {}, skipping ReDoS test: {}",
                    endpoint, e.getMessage());
            return findings;
        }

        long slowThreshold = Math.max(ABSOLUTE_SLOW_THRESHOLD_MS, baselineElapsed * BASELINE_MULTIPLIER);

        for (String field : fields) {
            for (String payload : REDOS_PAYLOADS) {
                boolean timedOut = false;
                long elapsed;
                long start = System.currentTimeMillis();
                try {
                    sendRequest(endpoint, httpClient, buildJsonBody(fields, field, payload));
                } catch (IOException e) {
                    // A connect/read timeout while processing this specific payload is itself
                    // strong evidence of a hang — treat it as the slowest possible signal rather
                    // than silently swallowing it like other test cases' generic catch blocks do.
                    timedOut = true;
                } catch (Exception e) {
                    logger.debug("Error testing ReDoS on {} field {}: {}", endpoint, field, e.getMessage());
                    continue;
                }
                elapsed = System.currentTimeMillis() - start;

                if (timedOut || elapsed > slowThreshold) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Regular Expression Denial of Service (ReDoS)",
                            String.format("Submitting a catastrophic-backtracking payload in the '%s' field " +
                                    "caused the response to take %s, versus a %dms baseline — indicating a " +
                                    "vulnerable regular expression is used to validate this field.",
                                    field, timedOut ? "longer than the connection timeout" : elapsed + "ms",
                                    baselineElapsed),
                            Severity.HIGH,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Avoid regular expressions with nested or overlapping quantifiers (e.g. " +
                            "(a+)+, (a|a)+) for user-supplied input validation. Use a regex engine with " +
                            "linear-time guarantees, impose a maximum input length before validation, or " +
                            "use a bounded validation timeout."
                    );
                    finding.setRequestDetails(endpoint.getMethod() + " " + endpoint.getFullUrl() +
                            "\nField: " + field + "\nPayload length: " + payload.length() + " characters");
                    finding.setEvidence(timedOut
                            ? "Request timed out (baseline was " + baselineElapsed + "ms)"
                            : "Response took " + elapsed + "ms (baseline: " + baselineElapsed + "ms)");
                    findings.add(finding);
                    return findings; // one confirmed hang is enough
                }
            }
        }

        return findings;
    }

    private List<String> extractBodyFieldNames(EndpointInfo endpoint) {
        String body = endpoint.getRequestBody();
        if (body != null && !body.isBlank()) {
            try {
                JsonNode root = objectMapper.readTree(body);
                if (root.isObject()) {
                    List<String> fields = new ArrayList<>();
                    Iterator<String> names = root.fieldNames();
                    while (names.hasNext()) {
                        fields.add(names.next());
                    }
                    if (!fields.isEmpty()) {
                        return fields;
                    }
                }
            } catch (Exception e) {
                logger.debug("Could not parse request body fields for {}, using common field names: {}",
                        endpoint, e.getMessage());
            }
        }
        return TARGET_FIELD_NAMES;
    }

    private String buildJsonBody(List<String> allFields, String targetField, String payload) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < allFields.size(); i++) {
            if (i > 0) sb.append(",");
            String field = allFields.get(i);
            String value = field.equals(targetField) ? payload : "test";
            sb.append("\"").append(field).append("\":\"").append(escapeJson(value)).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private HttpResponse sendRequest(EndpointInfo endpoint, HttpClient httpClient, String body) throws IOException {
        String url = endpoint.getFullUrl();
        String contentType = endpoint.getContentType() != null ? endpoint.getContentType() : "application/json";
        return switch (endpoint.getMethod().toUpperCase()) {
            case "POST"  -> httpClient.postWithStatus(url, Map.of(), contentType, body);
            case "PUT"   -> httpClient.putWithStatus(url, Map.of(), contentType, body);
            case "PATCH" -> httpClient.patchWithStatus(url, Map.of(), contentType, body);
            default -> null;
        };
    }

    private String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
