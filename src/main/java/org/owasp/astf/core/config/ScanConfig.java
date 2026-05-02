package org.owasp.astf.core.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.owasp.astf.core.EndpointInfo;

/**
 * Configuration for an API security scan.
 * <p>
 * This class contains all configuration parameters for executing a security scan,
 * including target information, authentication settings, test case selection,
 * threading options, output formats, and more.
 * </p>
 */
public class ScanConfig {
    // Target and scope configuration
    private String targetUrl;
    private List<EndpointInfo> endpoints;
    private boolean discoveryEnabled = true;
    private List<String> excludePatterns;
    private Map<String, String> headers;

    // Authentication settings
    private String basicAuthUsername;
    private String basicAuthPassword;
    private String apiKey;
    private String apiKeyHeader = "X-API-Key";
    private String bearerToken;

    // Proxy settings
    private String proxyHost;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;

    // Test case configuration
    private List<String> enabledTestCaseIds;
    private List<String> disabledTestCaseIds;

    // Execution settings
    private int threads = 10;
    private int timeoutMinutes = 30;
    private int requestDelayMs = 0;
    private int maxRequestsPerSecond = 0;
    private boolean followRedirects = true;
    private boolean validateCertificates = true;

    // Output settings
    private OutputFormat outputFormat = OutputFormat.JSON;
    private String outputFile;
    private boolean verbose = false;
    private int maxFindings = 0;
    private List<String> excludeSeverities;

    /**
     * Creates a new scan configuration with default settings.
     */
    public ScanConfig() {
        this.headers = new HashMap<>();
        this.endpoints = new ArrayList<>();
        this.enabledTestCaseIds = new ArrayList<>();
        this.disabledTestCaseIds = new ArrayList<>();
        this.excludePatterns = new ArrayList<>();
        this.excludeSeverities = new ArrayList<>();
    }

    // Target and scope getters/setters

    /**
     * Gets the target URL for the API scan.
     *
     * @return The target URL
     */
    public String getTargetUrl() {
        return targetUrl;
    }

    /**
     * Sets the target URL for the API scan.
     *
     * @param targetUrl The target URL
     */
    public void setTargetUrl(String targetUrl) {
        // Ensure target URL ends with a trailing slash
        if (targetUrl != null && !targetUrl.endsWith("/")) {
            this.targetUrl = targetUrl + "/";
        } else {
            this.targetUrl = targetUrl;
        }
    }

    /**
     * Gets the list of specific endpoints to scan.
     *
     * @return The endpoints to scan
     */
    public List<EndpointInfo> getEndpoints() {
        return endpoints;
    }

    /**
     * Sets the list of specific endpoints to scan.
     *
     * @param endpoints The endpoints to scan
     */
    public void setEndpoints(List<EndpointInfo> endpoints) {
        this.endpoints = endpoints;
    }

    /**
     * Adds an endpoint to scan.
     *
     * @param endpoint The endpoint to add
     */
    public void addEndpoint(EndpointInfo endpoint) {
        this.endpoints.add(endpoint);
    }

    /**
     * Checks if endpoint discovery is enabled.
     *
     * @return true if endpoint discovery is enabled
     */
    public boolean isDiscoveryEnabled() {
        return discoveryEnabled;
    }

    /**
     * Sets whether endpoint discovery is enabled.
     *
     * @param discoveryEnabled true to enable endpoint discovery
     */
    public void setDiscoveryEnabled(boolean discoveryEnabled) {
        this.discoveryEnabled = discoveryEnabled;
    }

    /**
     * Gets patterns to exclude from scanning.
     *
     * @return The exclude patterns
     */
    public List<String> getExcludePatterns() {
        return excludePatterns;
    }

    /**
     * Sets patterns to exclude from scanning.
     *
     * @param excludePatterns The exclude patterns
     */
    public void setExcludePatterns(List<String> excludePatterns) {
        this.excludePatterns = excludePatterns;
    }

    /**
     * Gets HTTP headers to include in requests.
     *
     * @return The HTTP headers
     */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /**
     * Sets HTTP headers to include in requests.
     *
     * @param headers The HTTP headers
     */
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    /**
     * Adds an HTTP header.
     *
     * @param name The header name
     * @param value The header value
     */
    public void addHeader(String name, String value) {
        this.headers.put(name, value);
    }

    // Authentication getters/setters

    /**
     * Gets the username for basic authentication.
     *
     * @return The basic auth username
     */
    public String getBasicAuthUsername() {
        return basicAuthUsername;
    }

    /**
     * Sets the username for basic authentication.
     *
     * @param basicAuthUsername The basic auth username
     */
    public void setBasicAuthUsername(String basicAuthUsername) {
        this.basicAuthUsername = basicAuthUsername;
    }

    /**
     * Gets the password for basic authentication.
     *
     * @return The basic auth password
     */
    public String getBasicAuthPassword() {
        return basicAuthPassword;
    }

    /**
     * Sets the password for basic authentication.
     *
     * @param basicAuthPassword The basic auth password
     */
    public void setBasicAuthPassword(String basicAuthPassword) {
        this.basicAuthPassword = basicAuthPassword;
    }

    /**
     * Gets the API key for authentication.
     *
     * @return The API key
     */
    public String getApiKey() {
        return apiKey;
    }

    /**
     * Sets the API key for authentication.
     *
     * @param apiKey The API key
     */
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    /**
     * Gets the header name for the API key.
     *
     * @return The API key header name
     */
    public String getApiKeyHeader() {
        return apiKeyHeader;
    }

    /**
     * Sets the header name for the API key.
     *
     * @param apiKeyHeader The API key header name
     */
    public void setApiKeyHeader(String apiKeyHeader) {
        this.apiKeyHeader = apiKeyHeader;
    }

    /**
     * Gets the bearer token for authentication.
     *
     * @return The bearer token
     */
    public String getBearerToken() {
        return bearerToken;
    }

    /**
     * Sets the bearer token for authentication.
     *
     * @param bearerToken The bearer token
     */
    public void setBearerToken(String bearerToken) {
        this.bearerToken = bearerToken;

        // Automatically add the Authorization header if not present
        if (bearerToken != null && !bearerToken.isEmpty() &&
                !headers.containsKey("Authorization")) {
            headers.put("Authorization", "Bearer " + bearerToken);
        }
    }

    // Proxy getters/setters

    /**
     * Gets the proxy host.
     *
     * @return The proxy host
     */
    public String getProxyHost() {
        return proxyHost;
    }

    /**
     * Sets the proxy host.
     *
     * @param proxyHost The proxy host
     */
    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    /**
     * Gets the proxy port.
     *
     * @return The proxy port
     */
    public int getProxyPort() {
        return proxyPort;
    }

    /**
     * Sets the proxy port.
     *
     * @param proxyPort The proxy port
     */
    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

    /**
     * Gets the proxy username for authentication.
     *
     * @return The proxy username
     */
    public String getProxyUsername() {
        return proxyUsername;
    }

    /**
     * Sets the proxy username for authentication.
     *
     * @param proxyUsername The proxy username
     */
    public void setProxyUsername(String proxyUsername) {
        this.proxyUsername = proxyUsername;
    }

    /**
     * Gets the proxy password for authentication.
     *
     * @return The proxy password
     */
    public String getProxyPassword() {
        return proxyPassword;
    }

    /**
     * Sets the proxy password for authentication.
     *
     * @param proxyPassword The proxy password
     */
    public void setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
    }

    // Test case configuration getters/setters

    /**
     * Gets the IDs of test cases to enable.
     *
     * @return The enabled test case IDs
     */
    public List<String> getEnabledTestCaseIds() {
        return enabledTestCaseIds;
    }

    /**
     * Sets the IDs of test cases to enable.
     *
     * @param enabledTestCaseIds The enabled test case IDs
     */
    public void setEnabledTestCaseIds(List<String> enabledTestCaseIds) {
        this.enabledTestCaseIds = enabledTestCaseIds;
    }

    /**
     * Gets the IDs of test cases to disable.
     *
     * @return The disabled test case IDs
     */
    public List<String> getDisabledTestCaseIds() {
        return disabledTestCaseIds;
    }

    /**
     * Sets the IDs of test cases to disable.
     *
     * @param disabledTestCaseIds The disabled test case IDs
     */
    public void setDisabledTestCaseIds(List<String> disabledTestCaseIds) {
        this.disabledTestCaseIds = disabledTestCaseIds;
    }

    // Execution settings getters/setters

    /**
     * Gets the number of threads to use for scanning.
     *
     * @return The thread count
     */
    public int getThreads() {
        return threads;
    }

    /**
     * Sets the number of threads to use for scanning.
     *
     * @param threads The thread count
     */
    public void setThreads(int threads) {
        this.threads = threads;
    }

    /**
     * Gets the timeout for the scan in minutes.
     *
     * @return The timeout in minutes
     */
    public int getTimeoutMinutes() {
        return timeoutMinutes;
    }

    /**
     * Sets the timeout for the scan in minutes.
     *
     * @param timeoutMinutes The timeout in minutes
     */
    public void setTimeoutMinutes(int timeoutMinutes) {
        this.timeoutMinutes = timeoutMinutes;
    }

    /**
     * Gets the delay between requests in milliseconds.
     *
     * @return The request delay in milliseconds
     */
    public int getRequestDelayMs() {
        return requestDelayMs;
    }

    /**
     * Sets the delay between requests in milliseconds.
     *
     * @param requestDelayMs The request delay in milliseconds
     */
    public void setRequestDelayMs(int requestDelayMs) {
        this.requestDelayMs = requestDelayMs;
    }

    /**
     * Gets the maximum number of requests per second.
     *
     * @return The maximum requests per second
     */
    public int getMaxRequestsPerSecond() {
        return maxRequestsPerSecond;
    }

    /**
     * Sets the maximum number of requests per second.
     *
     * @param maxRequestsPerSecond The maximum requests per second
     */
    public void setMaxRequestsPerSecond(int maxRequestsPerSecond) {
        this.maxRequestsPerSecond = maxRequestsPerSecond;
    }

    /**
     * Checks if the client should follow redirects.
     *
     * @return true if redirects should be followed
     */
    public boolean isFollowRedirects() {
        return followRedirects;
    }

    /**
     * Sets whether the client should follow redirects.
     *
     * @param followRedirects true to follow redirects
     */
    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }

    /**
     * Checks if SSL certificates should be validated.
     *
     * @return true if certificates should be validated
     */
    public boolean isValidateCertificates() {
        return validateCertificates;
    }

    /**
     * Sets whether SSL certificates should be validated.
     *
     * @param validateCertificates true to validate certificates
     */
    public void setValidateCertificates(boolean validateCertificates) {
        this.validateCertificates = validateCertificates;
    }

    // Output settings getters/setters

    /**
     * Gets the output format for the scan results.
     *
     * @return The output format
     */
    public OutputFormat getOutputFormat() {
        return outputFormat;
    }

    /**
     * Sets the output format for the scan results.
     *
     * @param outputFormat The output format
     */
    public void setOutputFormat(OutputFormat outputFormat) {
        this.outputFormat = outputFormat;
    }

    /**
     * Gets the output file path for the scan results.
     *
     * @return The output file path
     */
    public String getOutputFile() {
        return outputFile;
    }

    /**
     * Sets the output file path for the scan results.
     *
     * @param outputFile The output file path
     */
    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    /**
     * Checks if verbose output is enabled.
     *
     * @return true if verbose output is enabled
     */
    public boolean isVerbose() {
        return verbose;
    }

    /**
     * Sets whether verbose output is enabled.
     *
     * @param verbose true to enable verbose output
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * Gets the maximum number of findings to include in the results.
     *
     * @return The maximum number of findings
     */
    public int getMaxFindings() {
        return maxFindings;
    }

    /**
     * Sets the maximum number of findings to include in the results.
     *
     * @param maxFindings The maximum number of findings
     */
    public void setMaxFindings(int maxFindings) {
        this.maxFindings = maxFindings;
    }

    /**
     * Gets the severities to exclude from the results.
     *
     * @return The excluded severities
     */
    public List<String> getExcludeSeverities() {
        return excludeSeverities;
    }

    /**
     * Sets the severities to exclude from the results.
     *
     * @param excludeSeverities The excluded severities
     */
    public void setExcludeSeverities(List<String> excludeSeverities) {
        this.excludeSeverities = excludeSeverities;
    }

    /**
     * Enumeration of supported output formats.
     */
    public enum OutputFormat {
        /** JSON output format */
        JSON,
        /** XML output format */
        XML,
        /** HTML output format */
        HTML,
        /** SARIF output format for tool integration */
        SARIF
    }
}