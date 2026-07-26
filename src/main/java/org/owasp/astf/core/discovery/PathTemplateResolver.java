package org.owasp.astf.core.discovery;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Resolves an unresolved OpenAPI path-template placeholder (e.g. {@code /books/v1/{book_title}})
 * to a real, discovered value, so every test case gets to exercise the actual target resource
 * instead of a literal, non-existent placeholder string.
 * <p>
 * Originally implemented only inside {@code BrokenObjectLevelAuthorizationTestCase} (for its own
 * BOLA testing), then centralized here after live testing against VAmPI showed every <em>other</em>
 * test case — which has no resolution logic of its own — was sending the raw, unresolved
 * placeholder path on every request. That's not just a missed opportunity to test the real
 * endpoint: a literal, unencoded {@code {}} in an HTTP request line is invalid per RFC 3986, and
 * VAmPI's dev server simply hung the connection on such a request rather than responding at all
 * — meaning every non-BOLA test case was silently wasting its full connection timeout on every
 * templated endpoint, without producing a single meaningful finding for or against it.
 * <p>
 * {@link org.owasp.astf.core.Scanner} calls this once per discovered endpoint before test cases
 * run, so the fix benefits all of them without each needing its own copy of this logic.
 * Individual test cases (like BOLA) may still call this directly too — it's idempotent, so
 * calling it on an already-resolved endpoint is a fast no-op.
 */
public final class PathTemplateResolver {
    private static final Logger logger = LogManager.getLogger(PathTemplateResolver.class);

    private static final Pattern NUMERIC_ID_PATTERN = Pattern.compile("/(\\d+)(/|$)");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)",
            Pattern.CASE_INSENSITIVE);

    // Matches an unresolved OpenAPI path template placeholder, e.g. "/{book_title}" or
    // "/{username}" — a literal curly-brace segment straight from the spec, not a real value.
    private static final Pattern TEMPLATE_PLACEHOLDER_PATTERN = Pattern.compile("/\\{([^/{}]+)\\}");

    // Field names, in priority order, checked when looking for a plausible real identifier
    // value in a discovered collection endpoint's response body.
    private static final List<String> ID_LIKE_FIELD_NAMES = List.of(
            "id", "uuid", "username", "title", "slug", "name", "key", "code"
    );

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private PathTemplateResolver() {
    }

    /**
     * If the endpoint's path contains an unresolved OpenAPI template placeholder (e.g.
     * {@code /books/v1/{book_title}}), attempts to substitute it with a real, discovered value:
     * queries the endpoint's likely collection URL (the same path with the placeholder segment
     * and everything after it removed — e.g. {@code /books/v1}) and searches the response for a
     * plausible identifier field ({@link #ID_LIKE_FIELD_NAMES}).
     * <p>
     * Returns the original endpoint <strong>unchanged</strong> — never dropped, never removed
     * from consideration — whenever there's nothing to resolve (no placeholder, an already
     * concrete numeric/UUID id, or already marked {@link EndpointInfo#isResolvedFromTemplate()})
     * or resolution fails for any reason (no collection endpoint, empty response, no recognizable
     * id field). An unresolved endpoint is still tested by every test case exactly as it would
     * have been without this method existing — this only ever adds a better, real target on top,
     * never subtracts a candidate the scan would otherwise have covered.
     */
    public static EndpointInfo resolve(EndpointInfo endpoint, HttpClient httpClient) {
        if (endpoint.isResolvedFromTemplate()) {
            return endpoint; // already resolved (e.g. by Scanner) — idempotent no-op
        }

        String path = endpoint.getPath();
        if (NUMERIC_ID_PATTERN.matcher(path).find() || UUID_PATTERN.matcher(path).find()) {
            return endpoint; // already a concrete, testable id
        }

        Matcher placeholderMatcher = TEMPLATE_PLACEHOLDER_PATTERN.matcher(path);
        if (!placeholderMatcher.find()) {
            return endpoint; // no placeholder at all — nothing to resolve
        }

        String placeholder = placeholderMatcher.group();
        int placeholderIndex = path.indexOf(placeholder);
        String collectionPath = path.substring(0, placeholderIndex);
        if (collectionPath.isEmpty()) {
            return endpoint;
        }

        try {
            String collectionUrl = buildUrl(endpoint, collectionPath);
            HttpResponse response = httpClient.getWithStatus(collectionUrl, Map.of());
            if (response == null || !response.isSuccess() || response.getBody() == null || response.getBody().isBlank()) {
                return endpoint;
            }

            // The placeholder's own name (e.g. "book_title") is often the exact field name the
            // API itself uses in its responses — try that before falling back to generic
            // id-like names, since a fixed generic list can never cover every naming convention.
            String preferredFieldName = placeholderMatcher.group(1);

            JsonNode root = OBJECT_MAPPER.readTree(response.getBody());
            String idValue = findFirstIdLikeValue(root, 0, preferredFieldName);
            if (idValue == null) {
                return endpoint;
            }

            String resolvedPath = collectionPath + "/" + idValue + path.substring(placeholderIndex + placeholder.length());
            EndpointInfo resolved = new EndpointInfo(resolvedPath, endpoint.getMethod(), endpoint.getContentType(),
                    endpoint.getRequestBody(), endpoint.isRequiresAuthentication());
            resolved.setBaseUrl(endpoint.getBaseUrl());
            resolved.setResolvedFromTemplate(true);
            logger.info("Resolved path template {} -> {} using a value discovered from {}",
                    path, resolvedPath, collectionPath);
            return resolved;
        } catch (Exception e) {
            logger.debug("Could not resolve path template {} to a real value: {}", path, e.getMessage());
            return endpoint;
        }
    }

    /**
     * Recursively searches a JSON response (bounded to 3 levels deep) for a plausible identifier
     * value, checking arrays element-by-element and objects both for a direct field match and
     * for nested objects/arrays (handling common wrapper shapes like {@code {"data": [...]}} as
     * well as bare arrays or single objects).
     * <p>
     * Tries {@code preferredFieldName} (the path placeholder's own name, e.g. {@code
     * "book_title"}) first — APIs very often use the exact same field name in both the path
     * template and the response body — before falling back to {@link #ID_LIKE_FIELD_NAMES},
     * since no fixed generic list can cover every real-world naming convention.
     */
    private static String findFirstIdLikeValue(JsonNode node, int depth, String preferredFieldName) {
        if (node == null || depth > 3) {
            return null;
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                String found = findFirstIdLikeValue(item, depth + 1, preferredFieldName);
                if (found != null) return found;
            }
            return null;
        }
        if (node.isObject()) {
            if (preferredFieldName != null) {
                JsonNode preferred = node.get(preferredFieldName);
                if (preferred != null && preferred.isValueNode() && !preferred.asText().isBlank()) {
                    return preferred.asText();
                }
            }
            for (String fieldName : ID_LIKE_FIELD_NAMES) {
                JsonNode value = node.get(fieldName);
                if (value != null && value.isValueNode() && !value.asText().isBlank()) {
                    return value.asText();
                }
            }
            Iterator<JsonNode> children = node.elements();
            while (children.hasNext()) {
                String found = findFirstIdLikeValue(children.next(), depth + 1, preferredFieldName);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static String buildUrl(EndpointInfo endpoint, String path) {
        String base = endpoint.getBaseUrl();
        if (base == null || base.isEmpty()) return path;
        base = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        return base + (path.startsWith("/") ? path : "/" + path);
    }
}
