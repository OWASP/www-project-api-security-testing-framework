package org.owasp.astf.testcases;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
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

    // A deliberately bogus value used to establish a "this should fail" baseline for the
    // generalized bypass check below — works for any field shape (credential, coupon code,
    // discount token, ...), not just login-style username/password pairs.
    private static final String NOSQL_BASELINE_INVALID_VALUE = "astf-nosql-invalid-baseline-000";

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

    // Operator payloads expressed as a plain JSON *string* rather than an object — found necessary
    // by live-testing crAPI's apply_coupon endpoint: its DRF serializer declares coupon_code as a
    // CharField, so the object-shaped payloads above never reach the query layer at all (rejected
    // with a 400 before any injection point). A string-shaped payload passes that type check, and
    // still targets any code path that builds a query/condition via raw string interpolation or a
    // schema-less $where-style evaluation instead of a properly-typed query builder.
    //
    // Deliberately excludes bracket-notation key pollution (e.g. "field[$ne]=1"), which is a real
    // NoSQL bypass technique but only against a form/query-string body parser (qs/body-parser)
    // that expands "field[$ne]=1" into a nested {field: {$ne: 1}} object — a JSON request body has
    // no such expansion step, so that payload sent as a plain string *value* here can't achieve
    // what it's named for; it would just be a literal, inert string to any JSON-consuming backend.
    private static final List<String> NOSQL_STRING_OPERATOR_PAYLOADS = List.of(
            "$ne",
            "' || '1'=='1",
            "'; return true; var x='"
    );

    private static final List<String> NOSQL_ERROR_INDICATORS = List.of(
            "mongoerror", "bsonerror", "casterror", "e11000 duplicate key", "$where is not allowed",
            "mongoclient", "mongoose"
    );

    // Reused from the same class of false-positive fix as BrokenAuthenticationTestCase: a NoSQL
    // bypass attempt is only meaningful if the response doesn't ALSO carry an explicit failure
    // signal despite a 2xx status (some APIs return 200 on both success and failure). Broadened
    // beyond login-specific wording so the same check applies to any business-logic field (coupon
    // codes, discount tokens, ...), not just credentials.
    //
    // Split into two tiers rather than one flat list scanned against the whole response body:
    // unambiguous structured JSON key:value syntax (STRUCTURED_FAILURE_MARKERS) is safe to match
    // anywhere in the body, but generic words (TEXT_FAILURE_MARKERS) like "invalid" or "expired"
    // are common enough to appear in unrelated response content (a product name, an unrelated
    // nested field, ...) that scanning the whole body for them risks a false negative — the
    // generalized bypass check below would wrongly treat a genuine bypass as "failed" just because
    // some unrelated part of the JSON happened to contain one of these words. TEXT_FAILURE_MARKERS
    // is instead only checked against text pulled from fields that actually carry human-readable
    // status text (see MESSAGE_FIELD_NAMES / containsFailureMarker), falling back to a whole-body
    // scan only when the response isn't parseable JSON at all.
    private static final List<String> STRUCTURED_FAILURE_MARKERS = List.of(
            "\"status\":\"fail\"", "\"success\":false"
    );

    private static final List<String> TEXT_FAILURE_MARKERS = List.of(
            "incorrect", "invalid credentials", "invalid username", "invalid password",
            "authentication failed", "unauthorized", "not found", "does not exist", "invalid",
            "expired", "already used", "already applied", "denied", "rejected"
    );

    // JSON field names that conventionally carry human-readable status/error text — the only
    // place TEXT_FAILURE_MARKERS is checked against, to avoid matching those generic words inside
    // unrelated field values (e.g. a "coupon_code" or "message" echoed straight from the request).
    private static final List<String> MESSAGE_FIELD_NAMES = List.of(
            "message", "error", "errors", "detail", "details", "reason", "description", "msg",
            "status_message", "error_message"
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

        Map<String, JsonNode> fieldValues = extractBodyFieldValues(endpoint);
        List<String> targetFields = new ArrayList<>(fieldValues.keySet());
        boolean isAuthLike = isAuthLikeEndpoint(endpoint);

        findings.addAll(testSqlInjection(endpoint, httpClient, targetFields, fieldValues));
        if (findings.isEmpty()) {
            findings.addAll(testNoSqlInjection(endpoint, httpClient, targetFields, fieldValues, isAuthLike));
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
     * Uses the endpoint's own discovered request body fields and their original values when
     * available (more accurate — tests fields the API actually accepts, and lets sibling fields
     * keep their real JSON type), falling back to a common-name list with unknown types otherwise.
     * <p>
     * Preserving sibling fields' original types matters: {@link #buildJsonBody} previously forced
     * every non-target field to the string {@code "test"} regardless of its real shape, so an
     * endpoint with a strictly-typed sibling field (e.g. a numeric {@code amount} next to a
     * {@code coupon_code} under test) would reject every request — payload and baseline alike —
     * before the request ever reached the field actually being probed.
     */
    private Map<String, JsonNode> extractBodyFieldValues(EndpointInfo endpoint) {
        String body = endpoint.getRequestBody();
        if (body != null && !body.isBlank()) {
            try {
                JsonNode root = objectMapper.readTree(body);
                if (root.isObject() && root.size() > 0) {
                    Map<String, JsonNode> fields = new LinkedHashMap<>();
                    for (Map.Entry<String, JsonNode> entry : root.properties()) {
                        fields.put(entry.getKey(), entry.getValue());
                    }
                    return fields;
                }
            } catch (Exception e) {
                logger.debug("Could not parse request body fields for {}, using common field names: {}",
                        endpoint, e.getMessage());
            }
        }
        Map<String, JsonNode> fallback = new LinkedHashMap<>();
        for (String field : COMMON_BODY_FIELDS) {
            fallback.put(field, null); // unknown original type — buildJsonBody defaults to a string
        }
        return fallback;
    }

    private boolean isAuthLikeEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return AUTH_PATH_PATTERNS.stream().anyMatch(path::contains);
    }

    private List<Finding> testSqlInjection(EndpointInfo endpoint, HttpClient httpClient, List<String> fields,
                                            Map<String, JsonNode> fieldValues) {
        List<Finding> findings = new ArrayList<>();

        // Records each field's response to the bare single-quote payload (SQL_PAYLOADS.get(0)) as
        // it's sent below, so the behavioral fallback can reuse it instead of resending the exact
        // same request — avoids doubling live HTTP calls (and any side effects) per field.
        Map<String, HttpResponse> quoteResponseByField = new HashMap<>();

        for (String field : fields) {
            for (String payload : SQL_PAYLOADS) {
                try {
                    String body = buildJsonBody(fields, fieldValues, field, "\"" + escapeJson(payload) + "\"");
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
            findings.addAll(testSqlInjectionBehavioral(endpoint, httpClient, fields, fieldValues,
                    quoteResponseByField));
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
                                                       List<String> fields, Map<String, JsonNode> fieldValues,
                                                       Map<String, HttpResponse> quoteResponseByField) {
        List<Finding> findings = new ArrayList<>();

        for (String field : fields) {
            try {
                String baselineBody = buildJsonBody(fields, fieldValues, field, "\"astf-baseline-value\"");
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
                                              List<String> fields, Map<String, JsonNode> fieldValues,
                                              boolean isAuthLike) {
        List<Finding> findings = new ArrayList<>();

        List<String> allPayloads = new ArrayList<>(NOSQL_OPERATOR_PAYLOADS.size() +
                NOSQL_STRING_OPERATOR_PAYLOADS.size());
        allPayloads.addAll(NOSQL_OPERATOR_PAYLOADS);
        // String-shaped payloads need to be JSON string literals, not raw operator objects.
        for (String stringPayload : NOSQL_STRING_OPERATOR_PAYLOADS) {
            allPayloads.add("\"" + escapeJson(stringPayload) + "\"");
        }

        // The baseline request only depends on the field being tested, not on which operator
        // payload triggered the check — caching it here means at most one extra live request per
        // field, instead of one per successful payload (up to allPayloads.size() of them). This
        // matters because the endpoint under test may be a non-idempotent business action (e.g.
        // applying a coupon), so re-sending an equivalent "baseline" request for every payload
        // that happens to succeed would multiply real side effects against the target needlessly.
        Map<String, HttpResponse> baselineResponseByField = new HashMap<>();

        for (String field : fields) {
            for (String payload : allPayloads) {
                try {
                    String body = buildJsonBody(fields, fieldValues, field, payload);
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

                    // Generalized bypass check: ANY field on ANY endpoint (not just a
                    // credential-shaped field on an auth-like path — the original gating that
                    // missed crAPI's coupon-code field entirely). A payload response is only a
                    // real bypass signal if a baseline request using an obviously-invalid, but
                    // ordinarily-typed, value on the SAME field would be expected to fail —
                    // otherwise the endpoint may just accept (and ignore) any value.
                    if (response.isSuccess() && !containsFailureMarker(responseBody)) {
                        HttpResponse baseline;
                        if (baselineResponseByField.containsKey(field)) {
                            baseline = baselineResponseByField.get(field);
                        } else {
                            // Isolated from the outer catch so a transient failure on this one
                            // extra confirmation call doesn't get conflated with (and silently
                            // discard evidence from) the payload request that already succeeded.
                            try {
                                baseline = sendRequest(endpoint, httpClient,
                                        buildJsonBody(fields, fieldValues, field,
                                                "\"" + NOSQL_BASELINE_INVALID_VALUE + "\""));
                            } catch (Exception e) {
                                logger.debug("Error sending NoSQL baseline request on {} field {}: {}",
                                        endpoint, field, e.getMessage());
                                baseline = null;
                            }
                            baselineResponseByField.put(field, baseline);
                        }
                        String baselineBody = baseline != null ? baseline.getBody() : null;
                        boolean baselineFailed = baseline != null && baselineBody != null &&
                                (!baseline.isSuccess() || containsFailureMarker(baselineBody));

                        if (baselineFailed) {
                            boolean isCredentialField =
                                    CREDENTIAL_FIELD_NAMES.stream().anyMatch(field::equalsIgnoreCase);
                            String title = (isAuthLike && isCredentialField)
                                    ? "NoSQL Injection — Authentication Bypass"
                                    : "NoSQL Injection — Authorization/Logic Bypass";
                            findings.add(buildNoSqlFinding(endpoint, field, payload,
                                    "Request succeeded (HTTP " + response.getStatusCode() + ") when the '" +
                                    field + "' field was replaced with a NoSQL query operator, while an " +
                                    "ordinary invalid value on the same field failed (HTTP " +
                                    (baseline != null ? baseline.getStatusCode() : "?") + ")", Severity.CRITICAL,
                                    title));
                            return findings;
                        }
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

    /**
     * Builds a JSON body with {@code targetField} set to {@code rawValueJson} and every other
     * known field set to its original value from {@code originalValues} when available (falling
     * back to a benign {@code "test"} string when the original type is unknown — e.g. the
     * {@code COMMON_BODY_FIELDS} fallback, which has no real request body to draw from).
     * <p>
     * Preserving sibling fields' real JSON type (rather than flattening every non-target field to
     * a string) matters for strictly-typed APIs: a numeric field like {@code amount} sent as the
     * string {@code "test"} can fail type validation on its own, rejecting the whole request
     * before the field actually under test is ever evaluated — masking a real injection.
     */
    private String buildJsonBody(List<String> allFields, Map<String, JsonNode> originalValues,
                                  String targetField, String rawValueJson) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < allFields.size(); i++) {
            if (i > 0) sb.append(",");
            String field = allFields.get(i);
            sb.append("\"").append(field).append("\":");
            if (field.equals(targetField)) {
                sb.append(rawValueJson);
            } else {
                JsonNode original = originalValues.get(field);
                sb.append(original != null ? original.toString() : "\"test\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Whether {@code responseBody} carries an explicit failure/rejection signal, used to avoid
     * treating a 2xx response that actually represents a business-logic failure as a real bypass.
     * <p>
     * {@link #STRUCTURED_FAILURE_MARKERS} (unambiguous JSON key:value syntax) is checked against
     * the whole body. {@link #TEXT_FAILURE_MARKERS} (generic words like "invalid" or "expired")
     * is checked only against text pulled from fields conventionally used for human-readable
     * status/error messages ({@link #MESSAGE_FIELD_NAMES}) — scanning the whole body for words
     * that common would risk a false negative if they happened to appear in unrelated content
     * (e.g. a field simply echoing the submitted value back). Falls back to a whole-body scan only
     * when the response isn't parseable JSON, so plain-text error responses are still covered.
     */
    private boolean containsFailureMarker(String responseBody) {
        String lower = responseBody.toLowerCase();
        if (STRUCTURED_FAILURE_MARKERS.stream().anyMatch(lower::contains)) {
            return true;
        }

        String messageText = extractMessageText(responseBody);
        if (messageText != null) {
            return TEXT_FAILURE_MARKERS.stream().anyMatch(messageText.toLowerCase()::contains);
        }
        return TEXT_FAILURE_MARKERS.stream().anyMatch(lower::contains);
    }

    /** Concatenates the text of every field named like {@link #MESSAGE_FIELD_NAMES}, anywhere in
     *  the (possibly nested) JSON body — object- or array-rooted, e.g. a batch-style response
     *  like {@code [{"error": "..."}]} — or {@code null} if the body isn't parseable JSON at all. */
    private String extractMessageText(String responseBody) {
        try {
            JsonNode root = objectMapper.readTree(responseBody);
            if (!root.isObject() && !root.isArray()) {
                return null;
            }
            StringBuilder sb = new StringBuilder();
            collectMessageText(root, sb);
            return sb.length() > 0 ? sb.toString() : "";
        } catch (Exception e) {
            return null;
        }
    }

    private void collectMessageText(JsonNode node, StringBuilder sb) {
        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> entry : node.properties()) {
                JsonNode value = entry.getValue();
                if (MESSAGE_FIELD_NAMES.contains(entry.getKey().toLowerCase()) && value.isTextual()) {
                    sb.append(value.asText()).append(' ');
                }
                collectMessageText(value, sb); // nested message fields, e.g. {"error": {"message": "..."}}
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                collectMessageText(child, sb);
            }
        }
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
