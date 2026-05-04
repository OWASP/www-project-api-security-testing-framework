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

    // Deeply nested query designed to trigger resource exhaustion
    private static final String DEEP_QUERY;
    static {
        StringBuilder sb = new StringBuilder("{\"query\":\"{ a { b { c { d { e { f { g { h { i { j");
        for (int i = 0; i < 10; i++) sb.append(" }");
        sb.append("}}}\"}");
        DEEP_QUERY = sb.toString();
    }

    // Batch query — three introspection operations in one HTTP call
    private static final String BATCH_QUERY =
            "[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]";

    private static final String CONTENT_TYPE_JSON = "application/json";

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

        return findings;
    }

    // ── Helper: is this endpoint a GraphQL endpoint? ──────────────────────────

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

            if (response != null && response.isSuccess()) {
                String body = response.getBody();
                if (body != null && body.contains("__schema")) {
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

            if (response != null && response.isSuccess()) {
                // The server accepted the deeply nested query without rejecting it
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
                        " for a query nested 10+ levels deep");
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
}
