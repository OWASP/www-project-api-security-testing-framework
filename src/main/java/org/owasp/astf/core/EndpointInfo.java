package org.owasp.astf.core;

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

    /**
     * Returns the full URL by combining baseUrl and path.
     * Falls back to path alone if baseUrl is not set.
     */
    public String getFullUrl() {
        if (baseUrl != null && !baseUrl.isEmpty()) {
            String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
            String p = path.startsWith("/") ? path : "/" + path;
            return base + p;
        }
        return path;
    }

    @Override
    public String toString() {
        return method + " " + path;
    }
}