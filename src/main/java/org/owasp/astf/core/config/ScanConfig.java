package org.owasp.astf.core.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.owasp.astf.core.EndpointInfo;

/**
 * Configuration for a security scan.
 */
public class ScanConfig {
    private String targetUrl;
    private Map<String, String> headers;
    private List<EndpointInfo> endpoints;
    private int threads;
    private int timeoutMinutes;
    private boolean discoveryEnabled;
    private List<String> enabledTestCaseIds;
    private List<String> disabledTestCaseIds;
    private OutputFormat outputFormat;
    private String outputFile;
    private boolean verbose;

    public ScanConfig() {
        this.headers = new HashMap<>();
        this.endpoints = new ArrayList<>();
        this.threads = 10;
        this.timeoutMinutes = 30;
        this.discoveryEnabled = true;
        this.enabledTestCaseIds = new ArrayList<>();
        this.disabledTestCaseIds = new ArrayList<>();
        this.outputFormat = OutputFormat.JSON;
        this.verbose = false;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        // Ensure target URL ends with a trailing slash
        if (targetUrl != null && !targetUrl.endsWith("/")) {
            this.targetUrl = targetUrl + "/";
        } else {
            this.targetUrl = targetUrl;
        }
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public void addHeader(String name, String value) {
        this.headers.put(name, value);
    }

    public List<EndpointInfo> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<EndpointInfo> endpoints) {
        this.endpoints = endpoints;
    }

    public void addEndpoint(EndpointInfo endpoint) {
        this.endpoints.add(endpoint);
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public int getTimeoutMinutes() {
        return timeoutMinutes;
    }

    public void setTimeoutMinutes(int timeoutMinutes) {
        this.timeoutMinutes = timeoutMinutes;
    }

    public boolean isDiscoveryEnabled() {
        return discoveryEnabled;
    }

    public void setDiscoveryEnabled(boolean discoveryEnabled) {
        this.discoveryEnabled = discoveryEnabled;
    }

    public List<String> getEnabledTestCaseIds() {
        return enabledTestCaseIds;
    }

    public void setEnabledTestCaseIds(List<String> enabledTestCaseIds) {
        this.enabledTestCaseIds = enabledTestCaseIds;
    }

    public List<String> getDisabledTestCaseIds() {
        return disabledTestCaseIds;
    }

    public void setDisabledTestCaseIds(List<String> disabledTestCaseIds) {
        this.disabledTestCaseIds = disabledTestCaseIds;
    }

    public OutputFormat getOutputFormat() {
        return outputFormat;
    }

    public void setOutputFormat(OutputFormat outputFormat) {
        this.outputFormat = outputFormat;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public enum OutputFormat {
        JSON,
        XML,
        HTML,
        SARIF
    }
}
