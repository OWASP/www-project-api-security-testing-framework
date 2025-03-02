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

    @Override
    public String toString() {
        return method + " " + path;
    }
}