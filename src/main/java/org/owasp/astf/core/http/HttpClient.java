package org.owasp.astf.core.http;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;

import okhttp3.Authenticator;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.ConnectionPool;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.Credentials;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * HTTP client wrapper for making API requests.
 * <p>
 * This class provides a robust HTTP client implementation that supports:
 * <ul>
 *   <li>All common HTTP methods (GET, POST, PUT, DELETE, etc.)</li>
 *   <li>Various authentication methods</li>
 *   <li>Cookie handling</li>
 *   <li>Proxy configuration</li>
 *   <li>Connection pooling and timeout management</li>
 *   <li>Response processing with headers</li>
 * </ul>
 * </p>
 */
public class HttpClient {
    private static final Logger logger = LogManager.getLogger(HttpClient.class);

    private final OkHttpClient client;
    private final ScanConfig config;
    private final Map<String, String> defaultHeaders;
    private final Map<String, List<Cookie>> cookieStore = new HashMap<>();

    // Lazily-built client for HTTP/2 cleartext (h2c) prior-knowledge requests — see postH2c().
    private volatile OkHttpClient h2cClient;

    // Lazily-built, per-keystore-path clients for mTLS testing — see getWithClientCert().
    private final Map<String, OkHttpClient> clientCertClients = new ConcurrentHashMap<>();

    /**
     * Creates a new HTTP client with the specified configuration.
     *
     * @param config The scan configuration
     */
    public HttpClient(ScanConfig config) {
        this.config = config;
        this.defaultHeaders = new HashMap<>(config.getHeaders());

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(30))
                .writeTimeout(Duration.ofSeconds(30))
                .connectionPool(new ConnectionPool(20, 5, TimeUnit.MINUTES))
                .cookieJar(new InMemoryCookieJar())
                .followRedirects(true)
                .followSslRedirects(true);

        // Configure proxy if specified
        if (config.getProxyHost() != null && !config.getProxyHost().isEmpty()) {
            configureProxy(builder);
        }

        // Configure basic authentication if specified
        if (config.getBasicAuthUsername() != null && !config.getBasicAuthUsername().isEmpty()) {
            configureBasicAuth(builder);
        }

        this.client = builder.build();
    }

    /**
     * Makes a GET request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The response body as a string
     * @throws IOException If the request fails
     */
    public String get(String url, Map<String, String> headers) throws IOException {
        return executeRequest(createRequest(url, "GET", headers, null, null));
    }

    /**
     * Makes a POST request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The response body as a string
     * @throws IOException If the request fails
     */
    public String post(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequest(createRequest(url, "POST", headers, mediaType, requestBody));
    }

    /**
     * Makes a PUT request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The response body as a string
     * @throws IOException If the request fails
     */
    public String put(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequest(createRequest(url, "PUT", headers, mediaType, requestBody));
    }

    /**
     * Makes a DELETE request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The response body as a string
     * @throws IOException If the request fails
     */
    public String delete(String url, Map<String, String> headers) throws IOException {
        return executeRequest(createRequest(url, "DELETE", headers, null, null));
    }

    /**
     * Makes a PATCH request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The response body as a string
     * @throws IOException If the request fails
     */
    public String patch(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequest(createRequest(url, "PATCH", headers, mediaType, requestBody));
    }

    /**
     * Returns headers carrying the scan's secondary identity (a second, distinct authenticated
     * user), if one was configured via {@code --secondary-token}. Test cases that need to prove
     * a cross-user authorization bypass (e.g. BOLA) pass this map as the per-request header
     * override on the {@code *WithStatus} methods — OkHttp's {@code Request.Builder.header()}
     * replaces rather than appends, so this correctly overrides the primary identity's
     * Authorization header for that one request only, without altering the client's default
     * identity used everywhere else.
     *
     * @return A map with an Authorization header for the secondary identity, or an empty map if
     *         no secondary identity was configured (in which case cross-user checks should skip)
     */
    public Map<String, String> getSecondaryAuthHeaders() {
        String secondaryToken = config.getSecondaryBearerToken();
        if (secondaryToken == null || secondaryToken.isEmpty()) {
            return Map.of();
        }
        return Map.of("Authorization", "Bearer " + secondaryToken);
    }

    /** @return true if a normal (valid-identity) client certificate was configured via {@code --client-cert} */
    public boolean hasClientCert() {
        return config.getClientCertPath() != null && !config.getClientCertPath().isEmpty();
    }

    public String getClientCertPath() {
        return config.getClientCertPath();
    }

    public String getClientCertPassword() {
        return config.getClientCertPassword();
    }

    /** @return true if a deliberately invalid/untrusted client certificate was configured via {@code --invalid-client-cert} */
    public boolean hasInvalidClientCert() {
        return config.getInvalidClientCertPath() != null && !config.getInvalidClientCertPath().isEmpty();
    }

    public String getInvalidClientCertPath() {
        return config.getInvalidClientCertPath();
    }

    public String getInvalidClientCertPassword() {
        return config.getInvalidClientCertPassword();
    }

    /**
     * @return the bearer token configured for this scan (via {@code --token}), or {@code null}
     * if none was provided. Lets JWT-forgery test cases reuse the real, already-valid token's
     * own claims (e.g. its {@code sub}) instead of a generic placeholder identity that may not
     * resolve to any real account on the target.
     */
    public String getConfiguredBearerToken() {
        return config.getBearerToken();
    }

    /**
     * Sends a GET request presenting the client certificate from the given PKCS12 keystore,
     * for mTLS testing (e.g. confirming whether a server actually validates client certificates
     * rather than accepting any presented certificate, or validates the certificate's subject).
     * <p>
     * The server's own certificate is deliberately NOT validated by this client (a permissive
     * trust manager is used) — this method exists to probe how the SERVER behaves toward
     * different client identities, not to verify the server's identity to the caller.
     *
     * @param url The target URL (must be https://)
     * @param headers Additional headers to include
     * @param certPath Path to a PKCS12 keystore (.p12/.pfx) containing the client certificate and key
     * @param certPassword The keystore password
     * @return The full HTTP response
     * @throws IOException If the request fails, the keystore can't be read, or the certificate
     *                      is rejected at the TLS handshake level (itself a meaningful signal —
     *                      callers should treat such an exception as "certificate not accepted")
     */
    public HttpResponse getWithClientCert(String url, Map<String, String> headers,
                                           String certPath, String certPassword) throws IOException {
        OkHttpClient certClient = clientCertClients.computeIfAbsent(certPath,
                path -> buildClientCertClient(path, certPassword));
        Request request = createRequest(url, "GET", headers, null, null);
        try (Response response = certClient.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";
            Map<String, List<String>> responseHeaders = extractHeaders(response);
            return new HttpResponse(response.code(), body, responseHeaders);
        }
    }

    private OkHttpClient buildClientCertClient(String certPath, String certPassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream in = new FileInputStream(certPath)) {
                keyStore.load(in, certPassword != null ? certPassword.toCharArray() : new char[0]);
            }

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, certPassword != null ? certPassword.toCharArray() : new char[0]);

            // This client's purpose is to test how the SERVER validates the CLIENT certificate —
            // the server's certificate is intentionally not validated here.
            X509TrustManager trustAllServerCerts = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                public void checkServerTrusted(X509Certificate[] chain, String authType) { }
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(),
                    new X509TrustManager[]{trustAllServerCerts}, new SecureRandom());

            return client.newBuilder()
                    .sslSocketFactory(sslContext.getSocketFactory(), trustAllServerCerts)
                    .hostnameVerifier((hostname, session) -> true)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load client certificate from " + certPath, e);
        }
    }

    /**
     * Sends a POST request using HTTP/2 cleartext prior-knowledge (h2c) rather than HTTP/1.1.
     * <p>
     * gRPC's wire protocol is HTTP/2-only. OkHttp never attempts HTTP/2 over a plain
     * {@code "http://"} URL by default — without TLS there is no ALPN negotiation, so a
     * standard client silently falls back to HTTP/1.1, which a gRPC server cannot understand
     * at all (the connection is rejected outright). This method routes cleartext targets
     * through a dedicated client configured for {@link Protocol#H2_PRIOR_KNOWLEDGE} so the
     * request can actually reach a gRPC service.
     * <p>
     * {@code "https://"} targets are unaffected and continue to use the standard client, which
     * already negotiates HTTP/2 automatically via ALPN when the server supports it.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The full HTTP response
     * @throws IOException If the request fails (including when the target does not speak h2c)
     */
    public HttpResponse postH2c(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        Request request = createRequest(url, "POST", headers, mediaType, requestBody);

        OkHttpClient targetClient = url.startsWith("https://") ? client : h2cClient();
        try (Response response = targetClient.newCall(request).execute()) {
            String responseBody = response.body() != null ? response.body().string() : "";
            Map<String, List<String>> responseHeaders = extractHeaders(response);
            return new HttpResponse(response.code(), responseBody, responseHeaders);
        }
    }

    /**
     * Binary-safe sibling of {@link #postH2c}, for protocols like gRPC's reflection service whose
     * messages are protobuf-encoded binary data. {@code postH2c}'s {@code String} body/response
     * would corrupt arbitrary binary bytes that aren't valid UTF-8 when round-tripped through
     * Java's {@code String} (which is UTF-16 internally) — this method reads/writes raw bytes
     * throughout so the binary payload survives intact.
     *
     * @param url The target URL
     * @param headers Additional headers to include (the caller is responsible for setting
     *                 {@code Content-Type: application/grpc} and any gRPC-required headers)
     * @param body The raw request body bytes (e.g. a gRPC-framed protobuf message)
     * @return The raw response body bytes
     * @throws IOException If the request fails
     */
    public byte[] postBytesH2c(String url, Map<String, String> headers, byte[] body) throws IOException {
        RequestBody requestBody = RequestBody.create(body, MediaType.parse("application/grpc"));
        Request request = createRequest(url, "POST", headers, MediaType.parse("application/grpc"), requestBody);

        OkHttpClient targetClient = url.startsWith("https://") ? client : h2cClient();
        try (Response response = targetClient.newCall(request).execute()) {
            ResponseBody responseBody = response.body();
            return responseBody != null ? responseBody.bytes() : new byte[0];
        }
    }

    private OkHttpClient h2cClient() {
        OkHttpClient local = h2cClient;
        if (local == null) {
            synchronized (this) {
                local = h2cClient;
                if (local == null) {
                    local = client.newBuilder()
                            .protocols(List.of(Protocol.H2_PRIOR_KNOWLEDGE))
                            .build();
                    h2cClient = local;
                }
            }
        }
        return local;
    }

    /**
     * Gets the target URL from configuration.
     *
     * @return The configured target URL
     */
    public String getTargetUrl() {
        return config.getTargetUrl();
    }

    /**
     * Makes a GET request and returns the full response including status code.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The full HTTP response
     * @throws IOException If the request fails
     */
    public HttpResponse getWithStatus(String url, Map<String, String> headers) throws IOException {
        return executeRequestWithStatus(createRequest(url, "GET", headers, null, null));
    }

    /**
     * Makes a POST request and returns the full response including status code.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The full HTTP response
     * @throws IOException If the request fails
     */
    public HttpResponse postWithStatus(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequestWithStatus(createRequest(url, "POST", headers, mediaType, requestBody));
    }

    /**
     * Makes a PUT request and returns the full response including status code.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The full HTTP response
     * @throws IOException If the request fails
     */
    public HttpResponse putWithStatus(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequestWithStatus(createRequest(url, "PUT", headers, mediaType, requestBody));
    }

    /**
     * Makes a DELETE request and returns the full response including status code.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The full HTTP response
     * @throws IOException If the request fails
     */
    public HttpResponse deleteWithStatus(String url, Map<String, String> headers) throws IOException {
        return executeRequestWithStatus(createRequest(url, "DELETE", headers, null, null));
    }

    /**
     * Makes a PATCH request and returns the full response including status code.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The full HTTP response
     * @throws IOException If the request fails
     */
    public HttpResponse patchWithStatus(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequestWithStatus(createRequest(url, "PATCH", headers, mediaType, requestBody));
    }

    /**
     * Makes a HEAD request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The response headers
     * @throws IOException If the request fails
     */
    public Map<String, List<String>> head(String url, Map<String, String> headers) throws IOException {
        Response response = client.newCall(createRequest(url, "HEAD", headers, null, null)).execute();
        try {
            return extractHeaders(response);
        } finally {
            response.close();
        }
    }

    /**
     * Makes an asynchronous request to the specified URL.
     *
     * @param url The target URL
     * @param method The HTTP method
     * @param headers Additional headers to include
     * @param contentType The content type of the request (null for GET, HEAD, DELETE)
     * @param body The request body (null for GET, HEAD, DELETE)
     * @param callback The callback to handle the response
     */
    public void asyncRequest(String url, String method, Map<String, String> headers,
                             String contentType, String body, HttpResponseCallback callback) {
        try {
            MediaType mediaType = contentType != null ? MediaType.parse(contentType) : null;
            RequestBody requestBody = null;

            if (body != null && mediaType != null) {
                requestBody = RequestBody.create(body, mediaType);
            }

            Request request = createRequest(url, method, headers, mediaType, requestBody);

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    callback.onFailure(e);
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    try (ResponseBody responseBody = response.body()) {
                        String body = responseBody != null ? responseBody.string() : "";
                        Map<String, List<String>> headers = extractHeaders(response);
                        int statusCode = response.code();

                        callback.onSuccess(statusCode, headers, body);
                    }
                }
            });
        } catch (Exception e) {
            callback.onFailure(e);
        }
    }

    /**
     * Creates an HTTP request with the specified parameters.
     *
     * @param url The target URL
     * @param method The HTTP method
     * @param additionalHeaders Additional headers to include
     * @param mediaType The media type of the request (null for GET, HEAD, DELETE)
     * @param body The request body (null for GET, HEAD, DELETE)
     * @return The HTTP request
     */
    private Request createRequest(String url, String method, Map<String, String> additionalHeaders,
                                  MediaType mediaType, RequestBody body) {
        Request.Builder requestBuilder = new Request.Builder()
                .url(url);

        // Set the appropriate method and body
        switch (method.toUpperCase()) {
            case "GET" -> requestBuilder.get();
            case "HEAD" -> requestBuilder.head();
            case "DELETE" -> requestBuilder.delete();
            case "POST" -> requestBuilder.post(body);
            case "PUT" -> requestBuilder.put(body);
            case "PATCH" -> requestBuilder.patch(body);
            default -> {
                if (body != null) {
                    requestBuilder.method(method, body);
                } else {
                    requestBuilder.method(method, null);
                }
            }
        }

        // Add default headers from config
        for (Map.Entry<String, String> entry : defaultHeaders.entrySet()) {
            requestBuilder.header(entry.getKey(), entry.getValue());
        }

        // Add request-specific headers
        if (additionalHeaders != null) {
            for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }

        return requestBuilder.build();
    }

    /**
     * Executes a request and returns the response body as a string.
     *
     * @param request The HTTP request to execute
     * @return The response body as a string
     * @throws IOException If the request fails
     */
    private String executeRequest(Request request) throws IOException {
        try (Response response = client.newCall(request).execute()) {
            if (response.body() != null) {
                return response.body().string();
            }
            return "";
        }
    }

    /**
     * Executes a request and returns the full HTTP response including status code.
     *
     * @param request The HTTP request to execute
     * @return The full HTTP response
     * @throws IOException If the request fails
     */
    private HttpResponse executeRequestWithStatus(Request request) throws IOException {
        try (Response response = client.newCall(request).execute()) {
            String body = response.body() != null ? response.body().string() : "";
            Map<String, List<String>> headers = extractHeaders(response);
            return new HttpResponse(response.code(), body, headers);
        }
    }

    /**
     * Extracts headers from a response.
     *
     * @param response The HTTP response
     * @return A map of header names to values
     */
    private Map<String, List<String>> extractHeaders(Response response) {
        Map<String, List<String>> headers = new HashMap<>();

        for (String name : response.headers().names()) {
            headers.put(name, response.headers(name));
        }

        return headers;
    }

    /**
     * Configures proxy settings for the HTTP client.
     *
     * @param builder The OkHttpClient builder
     */
    private void configureProxy(OkHttpClient.Builder builder) {
        Proxy proxy = new Proxy(
                Proxy.Type.HTTP,
                new InetSocketAddress(config.getProxyHost(), config.getProxyPort())
        );

        builder.proxy(proxy);

        // Configure proxy authentication if needed
        if (config.getProxyUsername() != null && !config.getProxyUsername().isEmpty()) {
            Authenticator proxyAuthenticator = (route, response) -> {
                String credential = Credentials.basic(config.getProxyUsername(), config.getProxyPassword());
                return response.request().newBuilder()
                        .header("Proxy-Authorization", credential)
                        .build();
            };

            builder.proxyAuthenticator(proxyAuthenticator);
        }
    }

    /**
     * Configures basic authentication for the HTTP client.
     *
     * @param builder The OkHttpClient builder
     */
    private void configureBasicAuth(OkHttpClient.Builder builder) {
        Authenticator authenticator = (route, response) -> {
            String credential = Credentials.basic(config.getBasicAuthUsername(), config.getBasicAuthPassword());
            return response.request().newBuilder()
                    .header("Authorization", credential)
                    .build();
        };

        builder.authenticator(authenticator);
    }

    /**
     * In-memory cookie jar implementation for cookie management.
     */
    private class InMemoryCookieJar implements CookieJar {
        @Override
        public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
            String domain = url.host();

            if (!cookieStore.containsKey(domain)) {
                cookieStore.put(domain, new ArrayList<>());
            }

            // Replace existing cookies with the same name
            List<Cookie> domainCookies = cookieStore.get(domain);
            for (Cookie cookie : cookies) {
                // Remove existing cookie with same name if present
                domainCookies.removeIf(existingCookie -> existingCookie.name().equals(cookie.name()));

                // Add the new cookie
                domainCookies.add(cookie);
            }

            logger.debug("Cookies for {}: {}", domain, domainCookies.size());
        }

        @Override
        public List<Cookie> loadForRequest(HttpUrl url) {
            String domain = url.host();
            List<Cookie> validCookies = new ArrayList<>();

            if (cookieStore.containsKey(domain)) {
                List<Cookie> domainCookies = cookieStore.get(domain);
                for (Cookie cookie : domainCookies) {
                    if (cookie.matches(url)) {
                        validCookies.add(cookie);
                    }
                }
            }

            return validCookies;
        }
    }

    /**
     * Callback interface for asynchronous HTTP requests.
     */
    public interface HttpResponseCallback {
        /**
         * Called when the request is successful.
         *
         * @param statusCode The HTTP status code
         * @param headers The response headers
         * @param body The response body
         */
        void onSuccess(int statusCode, Map<String, List<String>> headers, String body);

        /**
         * Called when the request fails.
         *
         * @param e The exception that caused the failure
         */
        void onFailure(IOException e);

        void onFailure(Exception e);
    }
}