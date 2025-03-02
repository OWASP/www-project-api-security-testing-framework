package org.owasp.astf.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.testcases.TestCase;
import org.owasp.astf.testcases.TestCaseRegistry;

/**
 * The main scanner engine that orchestrates the API security testing process.
 */
public class Scanner {
    private static final Logger logger = LogManager.getLogger(Scanner.class);

    private final ScanConfig config;
    private final HttpClient httpClient;
    private final TestCaseRegistry testCaseRegistry;

    public Scanner(ScanConfig config) {
        this.config = config;
        this.httpClient = new HttpClient(config);
        this.testCaseRegistry = new TestCaseRegistry();
    }

    /**
     * Executes a full scan based on the provided configuration.
     *
     * @return The scan results containing all findings.
     */
    public ScanResult scan() {
        logger.info("Starting API security scan for target: {}", config.getTargetUrl());

        List<Finding> findings = new ArrayList<>();

        // Determine if we need to discover endpoints or use provided ones
        List<EndpointInfo> endpoints = new ArrayList<>();
        if (config.isDiscoveryEnabled() && config.getEndpoints().isEmpty()) {
            endpoints = discoverEndpoints();
        } else {
            endpoints = config.getEndpoints();
        }

        logger.info("Found {} endpoints to scan", endpoints.size());

        // Get applicable test cases
        List<TestCase> testCases = testCaseRegistry.getEnabledTestCases(config);
        logger.info("Running {} test cases", testCases.size());

        // Run test cases against endpoints
        ExecutorService executor = Executors.newFixedThreadPool(config.getThreads());

        for (EndpointInfo endpoint : endpoints) {
            for (TestCase testCase : testCases) {
                executor.submit(() -> {
                    try {
                        List<Finding> testFindings = testCase.execute(endpoint, httpClient);
                        synchronized (findings) {
                            findings.addAll(testFindings);
                        }
                    } catch (Exception e) {
                        logger.error("Error executing test case {} on endpoint {}: {}",
                                testCase.getId(), endpoint.getPath(), e.getMessage());
                    }
                });
            }
        }

        executor.shutdown();
        try {
            executor.awaitTermination(config.getTimeoutMinutes(), TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            logger.warn("Scan interrupted before completion");
            Thread.currentThread().interrupt();
        }

        ScanResult result = new ScanResult(config.getTargetUrl(), findings);
        logger.info("Scan completed. Found {} issues: {} high, {} medium, {} low severity",
                findings.size(),
                findings.stream().filter(f -> f.getSeverity() == Severity.HIGH).count(),
                findings.stream().filter(f -> f.getSeverity() == Severity.MEDIUM).count(),
                findings.stream().filter(f -> f.getSeverity() == Severity.LOW).count());

        return result;
    }

    /**
     * Attempts to discover API endpoints for the target.
     * This is a basic implementation that uses common paths and OpenAPI detection.
     *
     * @return A list of discovered endpoints
     */
    private List<EndpointInfo> discoverEndpoints() {
        logger.info("Attempting to discover API endpoints");
        List<EndpointInfo> endpoints = new ArrayList<>();

        // Try to find OpenAPI/Swagger specification
        List<String> specPaths = List.of(
                "/swagger/v1/swagger.json",
                "/swagger.json",
                "/api-docs",
                "/v2/api-docs",
                "/v3/api-docs",
                "/openapi.json"
        );

        for (String path : specPaths) {
            try {
                String url = config.getTargetUrl() + path;
                String response = httpClient.get(url, Map.of());

                if (response != null && !response.isEmpty()) {
                    logger.info("Found potential API specification at: {}", url);
                    // TODO: Parse OpenAPI spec and extract endpoints
                    break;
                }
            } catch (Exception e) {
                // Continue with next path
            }
        }

        // If no endpoints were found through specifications, return some common ones for testing
        if (endpoints.isEmpty()) {
            logger.info("No API spec found, using common paths for testing");
            endpoints.add(new EndpointInfo("/api/v1/users", "GET"));
            endpoints.add(new EndpointInfo("/api/v1/users", "POST"));
            endpoints.add(new EndpointInfo("/api/v1/users/{id}", "GET"));
            endpoints.add(new EndpointInfo("/api/v1/auth/login", "POST"));
            endpoints.add(new EndpointInfo("/api/v1/products", "GET"));
        }

        return endpoints;
    }
}