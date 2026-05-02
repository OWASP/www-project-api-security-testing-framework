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
 * Tests for API3:2023 Broken Object Property Level Authorization.
 *
 * This covers two previously separate categories: Excessive Data Exposure and Mass Assignment.
 * APIs may expose more properties than needed in responses (excessive data exposure) or allow
 * clients to update restricted object properties (mass assignment).
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/">OWASP API3:2023</a>
 */
public class BrokenObjectPropertyLevelAuthorizationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(BrokenObjectPropertyLevelAuthorizationTestCase.class);

    // Sensitive fields that should never be exposed in API responses
    private static final List<String> SENSITIVE_FIELDS = List.of(
            "password", "passwd", "secret", "token", "private_key", "privateKey",
            "ssn", "credit_card", "creditCard", "cvv", "pin", "api_secret", "apiSecret",
            "access_key", "accessKey", "private", "internal"
    );

    // Properties attackers might try to set via mass assignment
    private static final List<Map<String, Object>> PRIVILEGE_ESCALATION_PAYLOADS = List.of(
            Map.of("isAdmin", true, "role", "admin"),
            Map.of("admin", true, "is_admin", true),
            Map.of("role", "administrator", "permissions", List.of("*")),
            Map.of("active", true, "verified", true, "premium", true)
    );

    @Override
    public String getId() {
        return "ASTF-API3-2023";
    }

    @Override
    public String getName() {
        return "Broken Object Property Level Authorization";
    }

    @Override
    public String getDescription() {
        return "Tests for excessive data exposure (sensitive fields returned in responses) and " +
               "mass assignment vulnerabilities (ability to set restricted object properties).";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        findings.addAll(testExcessiveDataExposure(endpoint, httpClient));
        findings.addAll(testMassAssignment(endpoint, httpClient));

        return findings;
    }

    private List<Finding> testExcessiveDataExposure(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("GET")) {
            return findings;
        }

        try {
            HttpResponse response = httpClient.getWithStatus(endpoint.getFullUrl(), Map.of());

            if (response == null || !response.isSuccess()) {
                return findings;
            }

            String body = response.getBody().toLowerCase();
            List<String> exposedFields = new ArrayList<>();

            for (String field : SENSITIVE_FIELDS) {
                // Check if the response body contains sensitive field names (JSON key pattern)
                if (body.contains("\"" + field + "\"") || body.contains("'" + field + "'")) {
                    exposedFields.add(field);
                }
            }

            if (!exposedFields.isEmpty()) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Excessive Data Exposure - Sensitive Fields in Response",
                        "The API response contains sensitive fields that should not be returned to clients: " +
                        String.join(", ", exposedFields) + ". This can lead to credential exposure " +
                        "or information disclosure.",
                        Severity.HIGH,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Apply object-property-level authorization. Filter response data to include only " +
                        "properties that are needed by the client. Never return sensitive fields like " +
                        "passwords, secrets, or tokens in API responses."
                );
                finding.setEvidence("Sensitive fields found: " + String.join(", ", exposedFields));
                finding.setResponseDetails("HTTP " + response.getStatusCode() + " - body contained sensitive keys");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing excessive data exposure on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private List<Finding> testMassAssignment(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String method = endpoint.getMethod().toUpperCase();

        if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH")) {
            return findings;
        }

        for (Map<String, Object> payload : PRIVILEGE_ESCALATION_PAYLOADS) {
            try {
                String body = buildJsonPayload(payload);
                HttpResponse response = switch (method) {
                    case "POST"  -> httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                    case "PUT"   -> httpClient.putWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                    case "PATCH" -> httpClient.patchWithStatus(endpoint.getFullUrl(), Map.of(), "application/json", body);
                    default      -> null;
                };

                if (response != null && response.isSuccess()) {
                    String responseBody = response.getBody().toLowerCase();

                    // Check if the response reflects the privileged properties we tried to set
                    boolean privilegeAccepted = payload.keySet().stream()
                            .anyMatch(key -> responseBody.contains("\"" + key.toLowerCase() + "\""));

                    if (privilegeAccepted) {
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "Mass Assignment - Privilege Escalation via Object Properties",
                                "The API accepted and potentially applied restricted object properties " +
                                "submitted by the client, which may allow privilege escalation. " +
                                "Tested payload: " + body,
                                Severity.HIGH,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Implement an allowlist of properties that clients are permitted to set. " +
                                "Never bind client-supplied input directly to internal data models. " +
                                "Explicitly define which fields are writable per user role."
                        );
                        finding.setRequestDetails(method + " " + endpoint.getFullUrl() + "\nBody: " + body);
                        finding.setResponseDetails("HTTP " + response.getStatusCode());
                        findings.add(finding);
                        break;
                    }
                }
            } catch (Exception e) {
                logger.debug("Error testing mass assignment on {}: {}", endpoint, e.getMessage());
            }
        }

        return findings;
    }

    private String buildJsonPayload(Map<String, Object> payload) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : payload.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(entry.getKey()).append("\":");
            Object val = entry.getValue();
            if (val instanceof String) {
                sb.append("\"").append(val).append("\"");
            } else if (val instanceof List) {
                sb.append("[\"*\"]");
            } else {
                sb.append(val);
            }
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }
}
