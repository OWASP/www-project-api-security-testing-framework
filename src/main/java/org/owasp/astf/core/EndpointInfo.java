package org.owasp.astf.core;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Represents information about an API endpoint to be tested.
 */
public class EndpointInfo {
    private final String path;
    private final String method;
    private final String contentType;
    private String requestBody;
    private final boolean requiresAuthentication;
    private String baseUrl;

    // True once an unresolved OpenAPI path-template placeholder (e.g. "/{username}") has been
    // replaced with a real, discovered value (see org.owasp.astf.core.discovery.PathTemplateResolver).
    // Test cases that don't do ID substitution themselves (like BrokenObjectLevelAuthorizationTestCase's
    // cross-user check) use this to know a non-numeric/non-UUID last path segment is still a
    // legitimate, real object identifier rather than a literal, untestable template string.
    private boolean resolvedFromTemplate = false;

    public EndpointInfo(String path, String method) {
        this.path = path;
        this.method = method;
        this.contentType = "application/json";
        this.requiresAuthentication = true;
    }

    public EndpointInfo(String path, String method, String contentType, String requestBody, boolean requiresAuthentication) {
        this.path = path;
        this.method = method;
        this.contentType = contentType;
        this.requestBody = requestBody;
        this.requiresAuthentication = requiresAuthentication;
    }

    public String getPath() {
        return path;
    }

    public String getMethod() {
        return method;
    }

    public String getContentType() {
        return contentType;
    }

    public String getRequestBody() {
        return requestBody;
    }

    public boolean isRequiresAuthentication() {
        return requiresAuthentication;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public boolean isResolvedFromTemplate() {
        return resolvedFromTemplate;
    }

    public void setResolvedFromTemplate(boolean resolvedFromTemplate) {
        this.resolvedFromTemplate = resolvedFromTemplate;
    }

    /**
     * Returns the full URL by combining baseUrl and path.
     * Falls back to path alone if baseUrl is not set.
     * <p>
     * The path is percent-encoded before being appended. This matters for any endpoint whose
     * path still contains an unresolved OpenAPI template placeholder (e.g. {@code /{username}})
     * when a test case doesn't resolve or substitute it first: a literal, unencoded {@code {}} in
     * an HTTP request line is invalid per RFC 3986, and different servers handle that
     * inconsistently — some 400 quickly, but at least one real target (VAmPI's dev server, found
     * via live testing) simply hangs the connection with no response at all. Encoding makes the
     * request syntactically valid regardless, so it fails fast (typically a 404) instead of
     * hanging — turning an untestable endpoint into a merely-unproductive one rather than a
     * pipeline stall that silently wastes the timeout budget of every test case that reaches it.
     */
    public String getFullUrl() {
        String encodedPath = encodePath(path);
        if (baseUrl != null && !baseUrl.isEmpty()) {
            String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
            String p = encodedPath.startsWith("/") ? encodedPath : "/" + encodedPath;
            return base + p;
        }
        return encodedPath;
    }

    /**
     * Percent-encodes characters in {@code rawPath} that aren't valid in a raw URI path
     * (e.g. {@code {}}, spaces), while leaving already-valid path structure — including
     * legitimately pre-encoded sequences like {@code %20} — untouched.
     */
    private static String encodePath(String rawPath) {
        try {
            URI uri = new URI("http", "placeholder.invalid", rawPath, null);
            return uri.getRawPath();
        } catch (URISyntaxException e) {
            return rawPath; // fall back to the original string if it's unencodable for some other reason
        }
    }

    @Override
    public String toString() {
        return method + " " + path;
    }
}
