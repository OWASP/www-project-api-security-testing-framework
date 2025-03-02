package org.owasp.astf.core.http;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * HTTP client wrapper for making API requests.
 */
public class HttpClient {
    private static final Logger logger = LogManager.getLogger(HttpClient.class);

    private final OkHttpClient client;
    private final ScanConfig config;

    public HttpClient(ScanConfig config) {
        this.config = config;

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS);

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
        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .get();

        addHeaders(requestBuilder, headers);

        Request request = requestBuilder.build();
        try (Response response = client.newCall(request).execute()) {
            if (response.body() != null) {
                return response.body().string();
            }
            return "";
        }
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

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .post(requestBody);

        addHeaders(requestBuilder, headers);

        Request request = requestBuilder.build();
        try (Response response = client.newCall(request).execute()) {
            if (response.body() != null) {
                return response.body().string();
            }
            return "";
        }
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

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .put(requestBody);

        addHeaders(requestBuilder, headers);

        Request request = requestBuilder.build();
        try (Response response = client.newCall(request).execute()) {
            if (response.body() != null) {
                return response.body().string();
            }
            return "";
        }
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
        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .delete();

        addHeaders(requestBuilder, headers);

        Request request = requestBuilder.build();
        try (Response response = client.newCall(request).execute()) {
            if (response.body() != null) {
                return response.body().string();
            }
            return "";
        }
    }

    /**
     * Adds headers to the request builder.
     *
     * @param requestBuilder The request builder
     * @param additionalHeaders Additional headers to include
     */
    private void addHeaders(Request.Builder requestBuilder, Map<String, String> additionalHeaders) {
        // Add default headers from config
        for (Map.Entry<String, String> entry : config.getHeaders().entrySet()) {
            requestBuilder.header(entry.getKey(), entry.getValue());
        }

        // Add request-specific headers
        if (additionalHeaders != null) {
            for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }
    }
}