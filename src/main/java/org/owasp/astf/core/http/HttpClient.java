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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
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
import okhttp3.Interceptor;
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
    // Same client, minus any configured Basic Auth authenticator and minus cookies — used only
    // by the *NoAuth request variants. Without the authenticator override, a scan configured with
    // --username/--password would still leak credentials into a supposedly-unauthenticated
    // request: OkHttp's Authenticator fires automatically on any 401 response regardless of which
    // headers the original request carried (RetryAndFollowUpInterceptor invokes it transparently),
    // retrying with "Authorization: Basic ..." attached. Without the CookieJar override, any
    // session cookie captured earlier in the scan (e.g. from a login test case, via the shared
    // cookieStore backing InMemoryCookieJar) would still ride along on a "no-auth" request even
    // with Authorization/API-key headers correctly stripped — the same class of implicit-
    // credential leak, just through a different channel. A genuine no-auth baseline must carry
    // zero ambient credentials of any kind.
    private final OkHttpClient noAuthClient;
    private final ScanConfig config;
    private final Map<String, String> defaultHeaders;
    private final Map<String, List<Cookie>> cookieStore = new ConcurrentHashMap<>();

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
                .followRedirects(config.isFollowRedirects())
                .followSslRedirects(config.isFollowRedirects())
                // A network interceptor sees every hop, including followed redirects, after the
                // cookie jar has added its Cookie header, so it is the one place that can keep
                // credentials on the target for every request this client sends.
                .addNetworkInterceptor(this::pinCredentialsToScope);

        // Configure proxy if specified
        if (config.getProxyHost() != null && !config.getProxyHost().isEmpty()) {
            configureProxy(builder);
        }

        // Configure basic authentication if specified
        if (config.getBasicAuthUsername() != null && !config.getBasicAuthUsername().isEmpty()) {
            configureBasicAuth(builder);
        }

        this.client = builder.build();
        this.noAuthClient = this.client.newBuilder()
                .authenticator(Authenticator.NONE)
                .cookieJar(CookieJar.NO_COOKIES)
                .build();
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

    /** @return true if a secondary identity was configured via {@code --secondary-token} */
    public boolean hasSecondaryIdentity() {
        String secondaryToken = config.getSecondaryBearerToken();
        return secondaryToken != null && !secondaryToken.isEmpty();
    }

    /**
     * Sends a request as the secondary identity only. Unlike passing
     * {@link #getSecondaryAuthHeaders()} to a normal request, which only replaces
     * {@code Authorization}, this leaves off everything that belongs to the primary identity: the
     * configured API key, every custom header except the protocol headers (see
     * {@link #isPrimaryCredentialHeader}), cookies and the Basic Auth retry. Used
     * by cross-user checks so a success can only be explained by the secondary token.
     *
     * @param method      GET, POST, PUT, PATCH or DELETE (anything else is sent with that method name)
     * @param contentType content type of {@code body}; ignored for methods without a body
     * @param body        request body; ignored for GET and DELETE
     * @throws IllegalStateException if no secondary identity is configured
     */
    public HttpResponse sendWithStatusAsSecondary(String method, String url, String contentType, String body)
            throws IOException {
        if (!hasSecondaryIdentity()) {
            throw new IllegalStateException("No secondary identity configured");
        }
        Request request = buildBareRequest(method, url, contentType, body, getSecondaryAuthHeaders());
        return executeRequestWithStatus(request, noAuthClient);
    }

    /**
     * @return true if this scan was configured with a credential of its own: a bearer token, API
     *     key, Basic Auth, or a custom header that is part of the primary identity (any custom
     *     header other than the protocol headers Accept, Content-Type, User-Agent, Accept-Language
     *     and Accept-Encoding). A cookie the target set during the scan does not count: a scan
     *     with no credentials can still collect cookies, and retrying with those would not show
     *     anything about the configured identity. Checks that first probe without credentials use
     *     this to decide whether a credentialed retry can show anything the anonymous probe did not.
     */
    public boolean hasConfiguredCredentials() {
        if (config.getBearerToken() != null && !config.getBearerToken().isEmpty()) {
            return true;
        }
        if (config.getApiKey() != null && !config.getApiKey().isEmpty()) {
            return true;
        }
        if (config.getBasicAuthUsername() != null && !config.getBasicAuthUsername().isEmpty()) {
            return true;
        }
        return defaultHeaders.keySet().stream().anyMatch(this::isPrimaryCredentialHeader);
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
     * <p>
     * The request carries the certificate as its only credential: no bearer token, API key,
     * custom header other than the protocol headers, cookie or Basic Auth retry. Otherwise a server that ignores
     * the certificate but accepts the token would look like it accepts any certificate.
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
        Request request = buildBareRequest("GET", url, null, null, headers);
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

            return noAuthClient.newBuilder()
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
        return createRequest(url, method, additionalHeaders, mediaType, body, false);
    }

    /**
     * @param suppressCredentialHeaders when true, skips the default {@code Authorization} header,
     *     the configured API-key header and every custom header except the protocol headers (see
     *     {@link #isPrimaryCredentialHeader(String)}) that would otherwise always be attached from
     *     {@link #defaultHeaders}. Needed by any caller that
     *     deliberately wants to send a request with zero credentials — e.g. an "endpoint actually
     *     requires auth" baseline probe. Passing an empty {@code additionalHeaders} map is NOT
     *     enough to achieve that on its own: {@link #defaultHeaders} is always applied first
     *     regardless of what {@code additionalHeaders} contains, so the configured token or API
     *     key would otherwise ride along on every "no-auth" request for the life of the scan.
     */
    private Request createRequest(String url, String method, Map<String, String> additionalHeaders,
                                  MediaType mediaType, RequestBody body, boolean suppressCredentialHeaders) {
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

        // Add default headers from config, skipping credential headers when the caller
        // explicitly asked for an unauthenticated request.
        for (Map.Entry<String, String> entry : defaultHeaders.entrySet()) {
            if (suppressCredentialHeaders && isPrimaryCredentialHeader(entry.getKey())) {
                continue;
            }
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
     * @return the header names that carry credentials and should be omitted from a deliberately
     *     unauthenticated request: {@code Authorization} always, plus the configured API-key
     *     header (default {@code X-API-Key}) when an API key is set. Matching against this set
     *     must use {@link String#equalsIgnoreCase}, not {@code toLowerCase()} comparison — the
     *     latter is locale-sensitive (e.g. "I".toLowerCase() under a Turkish default locale
     *     produces "ı", not "i", which would silently fail to match "Authorization").
     */
    private Set<String> credentialHeaderNames() {
        Set<String> names = new HashSet<>();
        names.add("Authorization");
        if (config.getApiKey() != null && !config.getApiKey().isEmpty()) {
            names.add(config.getApiKeyHeader() != null ? config.getApiKeyHeader() : "X-API-Key");
        }
        return names;
    }

    // The only user-configured custom headers that a request without the primary identity still
    // carries: protocol headers that say how to frame or decode the exchange and cannot name a
    // user. Every other custom header is treated as part of the primary identity, because
    // identity often travels in headers whose names do not look like credentials (X-User-Id,
    // X-Hasura-Role, X-Forwarded-User, X-Remote-User, X-Account-Id behind a trusting gateway).
    private static final Set<String> PROTOCOL_HEADERS = Set.of(
            "accept", "content-type", "user-agent", "accept-language", "accept-encoding");

    /**
     * @return true if a default (config) header with this name belongs to the primary identity
     *     and is left off NoAuth and secondary-identity requests: {@code Authorization}, the
     *     configured API-key header, and every other user-configured custom header except the
     *     protocol headers in {@link #PROTOCOL_HEADERS}.
     */
    private boolean isPrimaryCredentialHeader(String headerName) {
        if (credentialHeaderNames().stream().anyMatch(headerName::equalsIgnoreCase)) {
            return true;
        }
        return PROTOCOL_HEADERS.stream().noneMatch(headerName::equalsIgnoreCase);
    }

    /**
     * Builds a request without any of the primary identity's credential headers (see
     * {@link #isPrimaryCredentialHeader}), then applies {@code extraHeaders}. Executed on
     * {@link #noAuthClient}, it also has no cookies and no Basic Auth retry.
     */
    private Request buildBareRequest(String method, String url, String contentType, String body,
                                     Map<String, String> extraHeaders) {
        String m = method.toUpperCase(java.util.Locale.ROOT);
        MediaType mediaType = null;
        RequestBody requestBody = null;
        if (!m.equals("GET") && !m.equals("HEAD") && !m.equals("DELETE")) {
            mediaType = MediaType.parse(contentType != null ? contentType : "application/json");
            requestBody = RequestBody.create(body != null ? body : "", mediaType);
        }
        return createRequest(url, m, extraHeaders, mediaType, requestBody, true);
    }

    /**
     * Makes a GET request with no credentials attached — not even the configured bearer token or
     * API key — for use as an "endpoint actually requires auth" baseline probe. See
     * {@link #createRequest(String, String, Map, MediaType, RequestBody, boolean)}.
     */
    public HttpResponse getWithStatusNoAuth(String url) throws IOException {
        return executeRequestWithStatus(createRequest(url, "GET", Map.of(), null, null, true), noAuthClient);
    }

    /** POST variant of {@link #getWithStatusNoAuth(String)}. */
    public HttpResponse postWithStatusNoAuth(String url, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequestWithStatus(createRequest(url, "POST", Map.of(), mediaType, requestBody, true), noAuthClient);
    }

    /** PUT variant of {@link #getWithStatusNoAuth(String)}. */
    public HttpResponse putWithStatusNoAuth(String url, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        return executeRequestWithStatus(createRequest(url, "PUT", Map.of(), mediaType, requestBody, true), noAuthClient);
    }

    /** DELETE variant of {@link #getWithStatusNoAuth(String)}. */
    public HttpResponse deleteWithStatusNoAuth(String url) throws IOException {
        return executeRequestWithStatus(createRequest(url, "DELETE", Map.of(), null, null, true), noAuthClient);
    }

    /** PATCH variant of {@link #getWithStatusNoAuth(String)}. */
    public HttpResponse patchWithStatusNoAuth(String url, String contentType, String body) throws IOException {
        return sendWithStatusNoAuth("PATCH", url, contentType, body);
    }

    /**
     * Any-method variant of {@link #getWithStatusNoAuth(String)}: sends {@code method} with no
     * credentials of any kind (no token, API key, custom header other than the protocol headers, cookie or Basic
     * Auth retry).
     *
     * @param contentType content type of {@code body}; ignored for GET, HEAD and DELETE
     * @param body        request body; ignored for GET, HEAD and DELETE
     */
    public HttpResponse sendWithStatusNoAuth(String method, String url, String contentType, String body)
            throws IOException {
        return executeRequestWithStatus(buildBareRequest(method, url, contentType, body, Map.of()), noAuthClient);
    }

    /** String-body GET variant of {@link #getWithStatusNoAuth(String)}, for callers that only need the response body. */
    public String getNoAuth(String url) throws IOException {
        return executeRequest(createRequest(url, "GET", Map.of(), null, null, true), noAuthClient);
    }

    /**
     * Executes a request and returns the response body as a string.
     *
     * @param request The HTTP request to execute
     * @return The response body as a string
     * @throws IOException If the request fails
     */
    private String executeRequest(Request request) throws IOException {
        return executeRequest(request, client);
    }

    private String executeRequest(Request request, OkHttpClient callClient) throws IOException {
        try (Response response = callClient.newCall(request).execute()) {
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
        return executeRequestWithStatus(request, client);
    }

    private HttpResponse executeRequestWithStatus(Request request, OkHttpClient callClient) throws IOException {
        try (Response response = callClient.newCall(request).execute()) {
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
            // Never replace an Authorization header the caller set explicitly (e.g. forged-token probes).
            if (response.request().header("Authorization") != null) {
                return null;
            }
            // Retry at most once: give up if an earlier attempt in this chain already got a 401.
            for (Response prior = response.priorResponse(); prior != null; prior = prior.priorResponse()) {
                if (prior.code() == 401) {
                    return null;
                }
            }
            // Only send the credentials to the configured target (or a scopeHosts entry),
            // never to some other host a redirect led to.
            HttpUrl target = HttpUrl.parse(config.getTargetUrl());
            if (target == null || !isInCredentialScope(response.request().url())) {
                return null;
            }
            String credential = Credentials.basic(config.getBasicAuthUsername(), config.getBasicAuthPassword());
            return response.request().newBuilder()
                    .header("Authorization", credential)
                    .build();
        };

        builder.authenticator(authenticator);
    }

    // Standard protocol headers that are never treated as credentials, even when the user set
    // them as custom headers: removing them would change how the request is framed or decoded.
    private static final Set<String> NEVER_STRIPPED = Set.of(
            "accept", "accept-encoding", "accept-language", "content-type", "content-length",
            "content-encoding", "transfer-encoding", "user-agent", "host", "connection",
            "proxy-authorization");

    /**
     * Network interceptor that keeps the scan's credentials on the target. A request to any
     * host:port other than the target (or a {@code scopeHosts} entry) is still sent, so discovery
     * and redirect handling are not reduced, but without the Authorization header, the API-key
     * header, any user-configured custom header, and cookies.
     */
    private Response pinCredentialsToScope(Interceptor.Chain chain) throws IOException {
        Request request = chain.request();
        HttpUrl url = request.url();
        if (isInCredentialScope(url)) {
            // OkHttp itself drops Authorization when a redirect changes host. A host the user
            // listed in scopeHosts is allowed to receive it, so put back the caller's value.
            if (request.header("Authorization") == null && !isTargetHost(url)) {
                String original = chain.call().request().header("Authorization");
                if (original != null) {
                    request = request.newBuilder().header("Authorization", original).build();
                }
            }
            return chain.proceed(request);
        }

        Request.Builder stripped = request.newBuilder();
        List<String> removed = new ArrayList<>();
        for (String name : request.headers().names()) {
            if (isCredentialForScope(name)) {
                stripped.removeHeader(name);
                removed.add(name);
            }
        }
        if (!removed.isEmpty()) {
            logger.debug("Request to {}:{} is outside the scan scope; sent without {}",
                    url.host(), url.port(), removed);
        }
        return chain.proceed(stripped.build());
    }

    private boolean isCredentialForScope(String headerName) {
        if (NEVER_STRIPPED.stream().anyMatch(headerName::equalsIgnoreCase)) {
            return false;
        }
        if ("Authorization".equalsIgnoreCase(headerName) || "Cookie".equalsIgnoreCase(headerName)
                || "Cookie2".equalsIgnoreCase(headerName)) {
            return true;
        }
        if (credentialHeaderNames().stream().anyMatch(headerName::equalsIgnoreCase)) {
            return true;
        }
        return defaultHeaders.keySet().stream().anyMatch(headerName::equalsIgnoreCase);
    }

    /**
     * @return true if the URL's host and port are the configured target's, or match an entry in
     *     {@code scopeHosts} ({@code host} for any port, {@code host:port} for that port only).
     *     With no parseable target URL there is nothing to pin to, and every host is in scope.
     */
    boolean isInCredentialScope(HttpUrl url) {
        HttpUrl target = config.getTargetUrl() != null ? HttpUrl.parse(config.getTargetUrl()) : null;
        if (target == null) {
            return true;
        }
        if (isTargetHost(url)) {
            return true;
        }
        for (String entry : config.getScopeHosts()) {
            if (scopeEntryMatches(entry, url)) {
                return true;
            }
        }
        return false;
    }

    private boolean isTargetHost(HttpUrl url) {
        HttpUrl target = config.getTargetUrl() != null ? HttpUrl.parse(config.getTargetUrl()) : null;
        return target != null && target.host().equalsIgnoreCase(url.host()) && target.port() == url.port();
    }

    private static boolean scopeEntryMatches(String entry, HttpUrl url) {
        if (entry == null || entry.isBlank()) {
            return false;
        }
        String e = entry.trim();
        String host;
        int port = -1;
        if (e.contains("://")) {
            HttpUrl parsed = HttpUrl.parse(e);
            if (parsed == null) {
                return false;
            }
            host = parsed.host();
            port = parsed.port();
        } else if (e.startsWith("[")) {
            int close = e.indexOf(']');
            if (close < 0) {
                return false;
            }
            host = e.substring(1, close);
            if (e.length() > close + 2 && e.charAt(close + 1) == ':') {
                port = parsePort(e.substring(close + 2));
                if (port < 0) {
                    return false;
                }
            }
        } else if (e.indexOf(':') > 0 && e.indexOf(':') == e.lastIndexOf(':')) {
            host = e.substring(0, e.indexOf(':'));
            port = parsePort(e.substring(e.indexOf(':') + 1));
            if (port < 0) {
                return false;
            }
        } else {
            host = e;
        }
        if (!host.equalsIgnoreCase(url.host())) {
            return false;
        }
        return port == -1 || port == url.port();
    }

    private static int parsePort(String s) {
        try {
            int p = Integer.parseInt(s.trim());
            return p > 0 && p <= 65535 ? p : -1;
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    /**
     * In-memory cookie jar implementation for cookie management.
     */
    private class InMemoryCookieJar implements CookieJar {
        @Override
        public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
            String domain = url.host();

            List<Cookie> domainCookies = cookieStore.computeIfAbsent(domain, d -> new CopyOnWriteArrayList<>());

            // Replace existing cookies with the same name. Locked so the remove+add pair is atomic
            // between writers; readers iterate the copy-on-write snapshot without locking.
            synchronized (domainCookies) {
                for (Cookie cookie : cookies) {
                    // Remove existing cookie with same name if present
                    domainCookies.removeIf(existingCookie -> existingCookie.name().equals(cookie.name()));

                    // Add the new cookie
                    domainCookies.add(cookie);
                }
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