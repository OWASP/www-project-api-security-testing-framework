package org.owasp.astf.core.http;

import java.util.List;
import java.util.Map;

/**
 * Represents an HTTP response including status code, headers, and body.
 */
public class HttpResponse {
    private final int statusCode;
    private final String body;
    private final Map<String, List<String>> headers;

    public HttpResponse(int statusCode, String body, Map<String, List<String>> headers) {
        this.statusCode = statusCode;
        this.body = body;
        this.headers = headers;
    }

    public int getStatusCode() { return statusCode; }
    public String getBody() { return body != null ? body : ""; }
    public Map<String, List<String>> getHeaders() { return headers; }

    public boolean isSuccess() { return statusCode >= 200 && statusCode < 300; }
    public boolean isUnauthorized() { return statusCode == 401; }
    public boolean isForbidden() { return statusCode == 403; }
    public boolean isNotFound() { return statusCode == 404; }
    public boolean isRateLimited() { return statusCode == 429; }
    public boolean isServerError() { return statusCode >= 500; }
    public boolean isRedirect() { return statusCode >= 300 && statusCode < 400; }

    public String getHeader(String name) {
        if (headers == null) return null;
        List<String> values = headers.get(name);
        if (values == null) {
            // Case-insensitive lookup
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                    values = entry.getValue();
                    break;
                }
            }
        }
        return values != null && !values.isEmpty() ? values.get(0) : null;
    }

    public boolean hasHeader(String name) {
        return getHeader(name) != null;
    }

    @Override
    public String toString() {
        return "HttpResponse{statusCode=" + statusCode + ", bodyLength=" + getBody().length() + "}";
    }
}
