package org.owasp.astf.testcases;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Tests ordinary REST endpoint body fields for SQL and NoSQL injection.
 *
 * <p>Other test cases in this framework only probe for injection in narrow circumstances:
 * {@code UnsafeConsumptionOfApisTestCase} only tests endpoints whose <em>path</em> matches
 * integration-style keywords ({@code webhook}, {@code proxy}, {@code sync}, ...), and
 * {@code GraphQLSecurityTestCase}'s resolver-injection check only targets GraphQL mutation
 * arguments. Neither covers an ordinary REST endpoint's JSON body fields regardless of the
 * endpoint's path or protocol — a gap found by tracing ASTF's actual findings against VAmPI's
 * and crAPI's own documented SQL/NoSQL injection vulnerabilities and finding neither was ever
 * attempted.</p>
 *
 * <p>Also tests unresolved OpenAPI path-template segments (e.g. {@code /users/v1/{username}})
 * directly with injection payloads, regardless of HTTP method — found necessary by live-testing
 * against VAmPI, whose actual documented SQL injection vulnerability is on a path parameter of a
 * GET endpoint, a surface the original body-only implementation of this test case couldn't
 * reach at all.</p>
 *
 * <p>Test case ID: {@code ASTF-INJECTION-2023} — injection doesn't map to a single numbered
 * OWASP API Security Top 10 (2023) category (the risk is distributed across several), so this
 * follows the same convention already used for GraphQL/gRPC/mTLS/LLM.</p>
 */
public class SqlNoSqlInjectionTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(SqlNoSqlInjectionTestCase.class);

    // Used when the endpoint's discovered request body doesn't have any fields to target —
    // common field names likely to be present on a real POST/PUT/PATCH body.
    private static final List<String> COMMON_BODY_FIELDS = List.of(
            "email", "username", "password", "search", "query", "filter", "name", "title", "id"
    );

    private static final List<String> CREDENTIAL_FIELD_NAMES = List.of("password", "pass", "pwd");
    private static final List<String> AUTH_PATH_PATTERNS = List.of("login", "auth", "signin", "session");

    // Matches an unresolved OpenAPI path template placeholder, e.g. "/{username}" — the literal
    // placeholder text, injected into directly rather than resolved to a real value first (unlike
    // BrokenObjectLevelAuthorizationTestCase's resolution, injection payloads don't need a real
    // resource to exist behind the parameter to trigger a vulnerable query).
    private static final Pattern PATH_TEMPLATE_PATTERN = Pattern.compile("/\\{([^/{}]+)\\}");

    // Non-destructive SQL injection payloads — tautology and UNION-based, no DDL/DML.
    private static final List<String> SQL_PAYLOADS = List.of(
            "'",
            "' OR '1'='1",
            "' OR 1=1-- -",
            "1' UNION SELECT NULL-- -",
            "'; SELECT 1-- -"
    );

    private static final List<String> SQL_ERROR_INDICATORS = List.of(
            "sql syntax", "sqlstate", "mysql_fetch", "ora-01756", "postgresql query failed",
            "sqlite3::", "unclosed quotation mark", "syntax error at or near", "pg::syntaxerror",
            "you have an error in your sql syntax", "npgsql.postgresexception",
            // Python/SQLAlchemy (Flask/Django) — found missing entirely via live testing against
            // VAmPI, whose real SQLi vulnerability produces exactly this error shape and was
            // silently missed until these were added. One of the most common web stacks, so this
            // was a significant blind spot, not a minor omission.
            "sqlalchemy.exc", "sqlite3.operationalerror", "sqlite3.programmingerror",
            "unrecognized token", "django.db.utils", "psycopg2.errors",
            // Java/JDBC and generic ORM error-wrapper class names
            "java.sql.sqlexception", "jdbcexception", "hibernate.exception",
            // Node.js drivers
            "sequelizedatabaseerror", "sqlite_error"
    );

    // MongoDB-style NoSQL operator injection — sent as the field's raw JSON value, not a string.
    private static final List<String> NOSQL_OPERATOR_PAYLOADS = List.of(
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "{\"$regex\": \".*\"}"
    );

    private static final List<String> NOSQL_ERROR_INDICATORS = List.of(
            "mongoerror", "bsonerror", "casterror", "e11000 duplicate key", "$where is not allowed",
            "mongoclient", "mongoose"
    );

    // Reused from the same class of false-positive fix as BrokenAuthenticationTestCase: a NoSQL
    // auth-bypass attempt is only meaningful if the response doesn't ALSO carry an explicit
    // failure signal despite a 2xx status (some APIs return 200 on both success and failure).
    private static final List<String> AUTH_FAILURE_BODY_MARKERS = List.of(
            "\"status\":\"fail\"", "\"success\":false", "incorrect", "invalid credentials",
            "invalid username", "invalid password", "authentication failed", "unauthorized"
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getId() {
        return "ASTF-INJECTION-2023";
    }

    @Override
    public String getName() {
        return "SQL/NoSQL Injection";
    }

    @Override
    public String getDescription() {
        return "Tests REST endpoint body fields for SQL and NoSQL injection, independent of " +
               "path naming — complementing the narrower, path-keyword-gated injection checks " +
               "elsewhere in this framework.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        List<Finding> findings = new ArrayList<>();
        logger.info("Executing {} test on {}", getId(), endpoint);

        findings.addAll(testPathParameterSqlInjection(endpoint, httpClient));
        if (!findings.isEmpty()) {
            return findings;
        }

        String method = endpoint.getMethod().toUpperCase();
        if (!method.equals("POST") && !method.equals("PUT") && !method.equals("PATCH")) {
            return findings;
        }

        List<String> targetFields = extractBodyFieldNames(endpoint);
        boolean isAuthLike = isAuthLikeEndpoint(endpoint);

        findings.addAll(testSqlInjection(endpoint, httpClient, targetFields));
        if (findings.isEmpty()) {
            findings.addAll(testNoSqlInjection(endpoint, httpClient, targetFields, isAuthLike));
        }
        return findings;
    }

    /**
     * Injects SQL payloads directly into the endpoint's dynamic path segment, regardless of HTTP
     * method. Unlike {@link #testSqlInjection}, this reaches GET/DELETE endpoints too, since a
     * path parameter doesn't need a request body to be present or exploitable — this is exactly
     * the shape of VAmPI's own documented SQL injection vulnerability (a GET endpoint with a
     * vulnerable username path parameter).
     * <p>
     * Handles two cases: an unresolved OpenAPI template placeholder (e.g. {@code /{username}} —
     * the literal placeholder text, when {@link org.owasp.astf.core.Scanner} didn't or couldn't
     * resolve it first), or an already-resolved real value in that same position (e.g. {@code
     * /name1}, per {@link EndpointInfo#isResolvedFromTemplate()} — Scanner resolves templates
     * centrally before test cases run, so this is the common case in a real scan). Either way,
     * the segment gets replaced with the injection payload rather than left alone.
     */
    private List<Finding> testPathParameterSqlInjection(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        String path = endpoint.getPath();
        String segmentToReplace;
        String segmentLabel;

        Matcher matcher = PATH_TEMPLATE_PATTERN.matcher(path);
        if (matcher.find()) {
            segmentToReplace = matcher.group(); // e.g. "/{username}" — still unresolved
            segmentLabel = matcher.group(1);
        } else if (endpoint.isResolvedFromTemplate()) {
            int lastSlash = path.lastIndexOf('/');
            if (lastSlash < 0 || lastSlash == path.length() - 1) {
                return findings;
            }
            segmentToReplace = path.substring(lastSlash); // e.g. "/name1" — already resolved
            segmentLabel = path.substring(lastSlash + 1);
        } else {
            return findings; // no dynamic path segment to inject into at all
        }

        for (String payload : SQL_PAYLOADS) {
            try {
                String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                String injectedPath = path.replace(segmentToReplace, "/" + encodedPayload);
                String url = buildUrl(endpoint, injectedPath);

                HttpResponse response = sendRequestToUrl(endpoint, httpClient, url);
                String body = response != null ? response.getBody() : null;
                if (body == null) {
                    continue;
                }
                String lower = body.toLowerCase();
                for (String indicator : SQL_ERROR_INDICATORS) {
                    if (lower.contains(indicator)) {
                        Finding finding = new Finding(
                                UUID.randomUUID().toString(),
                                "SQL Injection Vulnerability",
                                String.format("Submitting a SQL injection payload in the '%s' path parameter " +
                                        "caused a database error message to appear in the response, " +
                                        "indicating the value is passed into a SQL query without proper " +
                                        "parameterization or sanitization.",
                                        segmentLabel),
                                Severity.CRITICAL,
                                getId(),
                                endpoint.getMethod() + " " + endpoint.getPath(),
                                "Use parameterized queries or an ORM with proper escaping for all database " +
                                "access, including path parameters. Never concatenate user input directly " +
                                "into SQL statements, and disable verbose database error messages in production."
                        );
                        finding.setRequestDetails(endpoint.getMethod() + " " + url);
                        finding.setEvidence("Database error pattern found: " + indicator);
                        findings.add(finding);
                        return findings;
                    }
                }
            } catch (Exception e) {
                logger.debug("Error testing path-parameter SQL injection on {}: {}", endpoint, e.getMessage());
            }
        }
        return findings;
    }

    /**
     * Uses the endpoint's own discovered request body fields when available (more accurate —
     * tests fields the API actually accepts), falling back to a common-name list otherwise.
     */
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
        return COMMON_BODY_FIELDS;
    }

    private boolean isAuthLikeEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return AUTH_PATH_PATTERNS.stream().anyMatch(path::contains);
    }

    private List<Finding> testSqlInjection(EndpointInfo endpoint, HttpClient httpClient, List<String> fields) {
        List<Finding> findings = new ArrayList<>();

        // Records each field's response to the bare single-quote payload (SQL_PAYLOADS.get(0)) as
        // it's sent below, so the behavioral fallback can reuse it instead of resending the exact
        // same request — avoids doubling live HTTP calls (and any side effects) per field.
        Map<String, HttpResponse> quoteResponseByField = new HashMap<>();

        for (String field : fields) {
            for (String payload : SQL_PAYLOADS) {
                try {
                    String body = buildJsonBody(fields, field, "\"" + escapeJson(payload) + "\"");
                    HttpResponse response = sendRequest(endpoint, httpClient, body);
                    if (payload.equals(SQL_PAYLOADS.get(0))) {
                        quoteResponseByField.put(field, response);
                    }
                    String responseBody = response != null ? response.getBody() : null;

                    if (responseBody != null) {
                        String lower = responseBody.toLowerCase();
                        for (String indicator : SQL_ERROR_INDICATORS) {
                            if (lower.contains(indicator)) {
                                Finding finding = new Finding(
                                        UUID.randomUUID().toString(),
                                        "SQL Injection Vulnerability",
                                        String.format("Submitting a SQL injection payload in the '%s' field " +
                                                "caused a database error message to appear in the response, " +
                                                "indicating the value is passed into a SQL query without " +
                                                "proper parameterization or sanitization.", field),
                                        Severity.CRITICAL,
                                        getId(),
                                        endpoint.getMethod() + " " + endpoint.getPath(),
                                        "Use parameterized queries or an ORM with proper escaping for all " +
                                        "database access. Never concatenate user input directly into SQL " +
                                        "statements, and disable verbose database error messages in production."
                                );
                                finding.setRequestDetails(endpoint.getMethod() + " " + endpoint.getFullUrl() +
                                        "\nField: " + field + "\nPayload: " + payload);
                                finding.setEvidence("Database error pattern found: " + indicator);
                                findings.add(finding);
                                return findings; // one confirmed injection is enough for this endpoint
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Error testing SQL injection on {} field {}: {}", endpoint, field, e.getMessage());
                }
            }
        }

        if (findings.isEmpty()) {
            findings.addAll(testSqlInjectionBehavioral(endpoint, httpClient, fields, quoteResponseByField));
        }

        return findings;
    }

    /**
     * Fallback for when a SQL error is real but never reaches the response body — e.g. an API
     * whose own exception handler crashes a second time trying to serialize the raw driver
     * error, so the client only ever sees a generic 500 page with no database-specific text
     * (observed live against crAPI's {@code apply_coupon} endpoint: a bare single quote in
     * {@code coupon_code} produces a confirmed {@code psycopg2.errors.ProgrammingError} server-side,
     * but the response body is a content-free Django error page). Compares a bare single-quote
     * payload's status against a clean-value baseline on the same field: an unprompted 500 where
     * the identical request with an ordinary value succeeds is a weaker, but real, signal that
     * unescaped input reached the query layer.
     * <p>
     * Reuses each field's response to the bare single-quote payload from {@code quoteResponseByField}
     * (already sent once by {@link #testSqlInjection}'s own payload loop) instead of resending an
     * identical request — avoids doubling live HTTP calls, and any side effects, per field.
     */
    private List<Finding> testSqlInjectionBehavioral(EndpointInfo endpoint, HttpClient httpClient,
                                                       List<String> fields,
                                                       Map<String, HttpResponse> quoteResponseByField) {
        List<Finding> findings = new ArrayList<>();

        for (String field : fields) {
            try {
                String baselineBody = buildJsonBody(fields, field, "\"astf-baseline-value\"");
                HttpResponse baseline = sendRequest(endpoint, httpClient, baselineBody);
                if (baseline == null || baseline.getStatusCode() == 500) {
                    continue; // baseline itself errors — can't attribute a later 500 to the payload
                }

                HttpResponse response = quoteResponseByField.get(field);
                if (response != null && response.getStatusCode() == 500) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Possible SQL Injection (Behavioral)",
                            String.format("Submitting a single quote in the '%s' field caused an HTTP 500 " +
                                    "error, while an ordinary value on the same field succeeded (HTTP %d). " +
                                    "This is consistent with unescaped input reaching a database query, even " +
                                    "though no database-specific error text appeared in the response body.",
                                    field, baseline.getStatusCode()),
                            Severity.MEDIUM,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Use parameterized queries or an ORM with proper escaping for all database " +
                            "access. Also review server-side exception handling — an unhandled error " +
                            "surfacing as a generic 500 page (rather than a validation-level 4xx) with no " +
                            "body evidence often means a real vulnerability just isn't visible to a " +
                            "black-box scanner yet."
                    );
                    finding.setRequestDetails(endpoint.getMethod() + " " + endpoint.getFullUrl() +
                            "\nField: " + field + "\nPayload: '\nBaseline status: " + baseline.getStatusCode());
                    finding.setEvidence("HTTP 500 on a single-quote payload vs HTTP " + baseline.getStatusCode() +
                            " on a clean baseline value for the same field");
                    findings.add(finding);
                }
            } catch (Exception e) {
                logger.debug("Error testing behavioral SQL injection on {} field {}: {}",
                        endpoint, field, e.getMessage());
            }
        }

        return findings;
    }

    private List<Finding> testNoSqlInjection(EndpointInfo endpoint, HttpClient httpClient,
                                              List<String> fields, boolean isAuthLike) {
        List<Finding> findings = new ArrayList<>();

        for (String field : fields) {
            for (String payload : NOSQL_OPERATOR_PAYLOADS) {
                try {
                    String body = buildJsonBody(fields, field, payload);
                    HttpResponse response = sendRequest(endpoint, httpClient, body);
                    String responseBody = response != null ? response.getBody() : null;
                    if (response == null || responseBody == null) {
                        continue;
                    }
                    String lower = responseBody.toLowerCase();

                    for (String indicator : NOSQL_ERROR_INDICATORS) {
                        if (lower.contains(indicator)) {
                            findings.add(buildNoSqlFinding(endpoint, field, payload,
                                    "NoSQL error pattern found: " + indicator, Severity.MEDIUM,
                                    "NoSQL Injection — Database Error Disclosed"));
                            return findings;
                        }
                    }

                    // Auth-bypass pattern: a credential-shaped field, on an auth-like endpoint,
                    // accepting an operator payload (e.g. {"password": {"$ne": null}}) and
                    // succeeding — the classic NoSQL login-bypass vulnerability class.
                    boolean isCredentialField = CREDENTIAL_FIELD_NAMES.stream().anyMatch(field::equalsIgnoreCase);
                    if (isAuthLike && isCredentialField && response.isSuccess()
                            && AUTH_FAILURE_BODY_MARKERS.stream().noneMatch(lower::contains)) {
                        findings.add(buildNoSqlFinding(endpoint, field, payload,
                                "Authentication succeeded (HTTP " + response.getStatusCode() +
                                ") when the '" + field + "' field was replaced with a MongoDB query operator " +
                                "instead of a string value", Severity.CRITICAL,
                                "NoSQL Injection — Authentication Bypass"));
                        return findings;
                    }
                } catch (Exception e) {
                    logger.debug("Error testing NoSQL injection on {} field {}: {}", endpoint, field, e.getMessage());
                }
            }
        }

        return findings;
    }

    private Finding buildNoSqlFinding(EndpointInfo endpoint, String field, String payload,
                                       String evidence, Severity severity, String title) {
        Finding finding = new Finding(
                UUID.randomUUID().toString(),
                title,
                String.format("Submitting a MongoDB-style query operator in the '%s' field produced a " +
                        "result indicating the value is passed into a NoSQL query without proper " +
                        "type validation or sanitization.", field),
                severity,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Validate that user-supplied fields are the expected scalar type before using them in a " +
                "database query (reject objects/operators where a string or number is expected). Use a " +
                "schema-validation layer (e.g. JSON Schema) ahead of the database access layer, and avoid " +
                "passing raw client-supplied objects directly into query builders."
        );
        finding.setRequestDetails(endpoint.getMethod() + " " + endpoint.getFullUrl() +
                "\nField: " + field + "\nPayload: " + payload);
        finding.setEvidence(evidence);
        return finding;
    }

    /** Builds a JSON body with every known field set to a benign default, except {@code targetField}. */
    private String buildJsonBody(List<String> allFields, String targetField, String rawValueJson) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < allFields.size(); i++) {
            if (i > 0) sb.append(",");
            String field = allFields.get(i);
            sb.append("\"").append(field).append("\":");
            sb.append(field.equals(targetField) ? rawValueJson : "\"test\"");
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

    /** Like {@link #sendRequest}, but targets an explicit URL (for path-parameter injection) and
     *  covers GET/DELETE as well, since a path parameter needs no request body to be exploitable. */
    private HttpResponse sendRequestToUrl(EndpointInfo endpoint, HttpClient httpClient, String url) throws IOException {
        String contentType = endpoint.getContentType() != null ? endpoint.getContentType() : "application/json";
        return switch (endpoint.getMethod().toUpperCase()) {
            case "GET"    -> httpClient.getWithStatus(url, Map.of());
            case "DELETE" -> httpClient.deleteWithStatus(url, Map.of());
            case "POST"   -> httpClient.postWithStatus(url, Map.of(), contentType, "{}");
            case "PUT"    -> httpClient.putWithStatus(url, Map.of(), contentType, "{}");
            case "PATCH"  -> httpClient.patchWithStatus(url, Map.of(), contentType, "{}");
            default -> null;
        };
    }

    private String buildUrl(EndpointInfo endpoint, String path) {
        String base = endpoint.getBaseUrl();
        if (base == null || base.isEmpty()) return path;
        base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        return base + (path.startsWith("/") ? path : "/" + path);
    }
}
