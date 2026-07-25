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

    // Introspects mutation fields, their argument types/names, AND their own return type, so
    // injection payloads can be sent to real mutations discovered from the schema (rather than
    // guessed field names) with a request shape the resolver will actually accept.
    private static final String MUTATION_INTROSPECTION_QUERY =
            "{\"query\":\"{__schema{mutationType{fields{name " +
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

        List<MutationCandidate> candidates;
        try {
            HttpResponse introspectionResponse = httpClient.postWithStatus(
                    endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, MUTATION_INTROSPECTION_QUERY);

            if (!isAcceptedGraphQLQuery(introspectionResponse)) {
                logger.debug("Skipping resolver injection test — mutation introspection unavailable on {}", endpoint);
                return findings;
            }
            candidates = extractStringArgMutations(introspectionResponse.getBody());
        } catch (Exception e) {
            logger.debug("Error introspecting mutations on {}: {}", endpoint, e.getMessage());
            return findings;
        }

        for (MutationCandidate candidate : candidates) {
            String selectionSet = resolveSelectionSet(candidate.returnTypeName(), endpoint, httpClient, 0);

            for (String payload : RESOLVER_INJECTION_PAYLOADS) {
                try {
                    String escapedPayload = payload.replace("\\", "\\\\").replace("\"", "\\\"");
                    String argList = buildArgumentList(candidate, escapedPayload);
                    String mutation = String.format("mutation{%s(%s)%s}",
                            candidate.name(), argList, selectionSet);
                    String requestBody = "{\"query\":\"" + mutation + "\"}";

                    HttpResponse response = httpClient.postWithStatus(
                            endpoint.getFullUrl(), Map.of(), CONTENT_TYPE_JSON, requestBody);
                    String body = response != null ? response.getBody() : null;

                    if (response != null && response.isSuccess() && body != null) {
                        String lowerBody = body.toLowerCase();
                        for (String indicator : RESOLVER_INJECTION_INDICATORS) {
                            if (lowerBody.contains(indicator.toLowerCase())) {
                                Finding f = new Finding(
                                        UUID.randomUUID().toString(),
                                        "GraphQL Resolver Injection Vulnerability",
                                        String.format("The mutation '%s' appears to pass its '%s' argument " +
                                                "unsanitized into a resolver that executes it (SQL query, " +
                                                "shell command, or renders it unescaped), based on the " +
                                                "detected pattern '%s' in the response.",
                                                candidate.name(), candidate.targetArgName(), indicator),
                                        Severity.CRITICAL,
                                        getId(),
                                        "POST " + endpoint.getPath() + " (mutation " + candidate.name() + ")",
                                        "Never build SQL queries or shell commands by concatenating resolver " +
                                        "arguments. Use parameterized queries for database access, avoid " +
                                        "shelling out entirely where possible, and escape/validate all " +
                                        "resolver input before use, output, or persistence."
                                );
                                f.setEvidence("Payload: " + payload + "\nPattern found: " + indicator);
                                findings.add(f);
                                return findings; // One confirmed resolver injection is enough
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Error testing resolver injection on mutation {}.{}: {}",
                            candidate.name(), candidate.targetArgName(), e.getMessage());
                }
            }
        }

        return findings;
    }

    private record ArgSpec(String name, String typeName) { }

    private record MutationCandidate(String name, String targetArgName, List<ArgSpec> allArgs,
                                      String returnTypeName) { }

    /**
     * Parses the mutation-introspection response and returns, for each mutation field with at
     * least one String-typed argument, its name, its first String argument (the injection
     * target), every argument the mutation accepts (so all of them can be given a valid default —
     * see {@link #testResolverInjection}), and its own resolved return type name. Bounded to the
     * first 5 mutations found, to keep request volume reasonable.
     */
    List<MutationCandidate> extractStringArgMutations(String introspectionBody) {
        List<MutationCandidate> results = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(introspectionBody);
            JsonNode fields = root.path("data").path("__schema").path("mutationType").path("fields");
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
