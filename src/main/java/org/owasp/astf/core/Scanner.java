package org.owasp.astf.core;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.discovery.EndpointDiscoveryService;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.testcases.TestCase;
import org.owasp.astf.testcases.TestCaseRegistry;

/**
 * The main scanner engine that orchestrates the API security testing process.
 * This class is responsible for:
 * <ul>
 *   <li>Initializing and executing the scan based on configuration</li>
 *   <li>Managing endpoint discovery or using provided endpoints</li>
 *   <li>Coordinating test case execution across endpoints</li>
 *   <li>Collecting and aggregating findings</li>
 *   <li>Providing progress updates and metrics</li>
 * </ul>
 */
public class Scanner {
    private static final Logger logger = LogManager.getLogger(Scanner.class);

    private final ScanConfig config;
    private final HttpClient httpClient;
    private final TestCaseRegistry testCaseRegistry;
    private final EndpointDiscoveryService discoveryService;

    // Scan metrics and tracking
    private final AtomicInteger completedTasks = new AtomicInteger(0);
    private final AtomicInteger totalTasks = new AtomicInteger(0);
    private final Map<Severity, AtomicInteger> findingsBySeverity = new ConcurrentHashMap<>();
    private LocalDateTime scanStartTime;
    private LocalDateTime scanEndTime;

    /**
     * Creates a new scanner with the specified configuration.
     *
     * @param config The scan configuration
     */
    public Scanner(ScanConfig config) {
        this.config = config;
        this.httpClient = new HttpClient(config);
        this.testCaseRegistry = new TestCaseRegistry();
        this.discoveryService = new EndpointDiscoveryService(config, httpClient);

        // Initialize severity counters
        for (Severity severity : Severity.values()) {
            findingsBySeverity.put(severity, new AtomicInteger(0));
        }
    }

    /**
     * Executes a full scan based on the provided configuration.
     *
     * @return The scan results containing all findings
     */
    public ScanResult scan() {
        scanStartTime = LocalDateTime.now();
        List<Finding> findings = new ArrayList<>();

        try {
            logger.info("Starting API security scan for target: {}", config.getTargetUrl());

            // Determine if we need to discover endpoints or use provided ones
            List<EndpointInfo> endpoints = new ArrayList<>();
            if (config.isDiscoveryEnabled() && config.getEndpoints().isEmpty()) {
                logger.info("No endpoints provided. Attempting endpoint discovery...");
                endpoints = discoverEndpoints();
            } else {
                endpoints = config.getEndpoints();
                logger.info("Using {} provided endpoints", endpoints.size());
            }

            if (endpoints.isEmpty()) {
                logger.warn("No endpoints found to scan. Check target URL or provide endpoints manually.");
                return createEmptyScanResult();
            }

            // Get applicable test cases
            List<TestCase> testCases = testCaseRegistry.getEnabledTestCases(config);
            logger.info("Running {} test cases against {} endpoints", testCases.size(), endpoints.size());

            // Calculate total tasks for progress tracking
            totalTasks.set(endpoints.size() * testCases.size());

            // Run test cases against endpoints using virtual threads (Java 21)
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                List<CompletableFuture<Void>> futures = new ArrayList<>();

                for (EndpointInfo endpoint : endpoints) {
                    for (TestCase testCase : testCases) {
                        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                            try {
                                logger.debug("Executing {} on {}", testCase.getId(), endpoint);
                                List<Finding> testFindings = testCase.execute(endpoint, httpClient);

                                if (!testFindings.isEmpty()) {
                                    synchronized (findings) {
                                        findings.addAll(testFindings);

                                        // Update severity counters
                                        for (Finding finding : testFindings) {
                                            findingsBySeverity.get(finding.getSeverity()).incrementAndGet();
                                        }
                                    }

                                    logger.debug("Found {} issues with {} on {}",
                                            testFindings.size(), testCase.getId(), endpoint);
                                }
                            } catch (Exception e) {
                                logger.error("Error executing test case {} on endpoint {}: {}",
                                        testCase.getId(), endpoint.getPath(), e.getMessage());
                                logger.debug("Exception details:", e);
                            } finally {
                                // Update progress
                                int completed = completedTasks.incrementAndGet();
                                if (completed % 10 == 0 || completed == totalTasks.get()) {
                                    logProgress();
                                }
                            }
                        }, executor);

                        futures.add(future);
                    }
                }

                // Wait for all tasks to complete or timeout
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                        .orTimeout(config.getTimeoutMinutes(), TimeUnit.MINUTES)
                        .exceptionally(ex -> {
                            logger.warn("Scan interrupted or timed out before completion: {}", ex.getMessage());
                            return null;
                        })
                        .join();
            }

            logger.info("Scan completed. Found {} issues: {} critical, {} high, {} medium, {} low, {} info",
                    findings.size(),
                    findingsBySeverity.get(Severity.CRITICAL).get(),
                    findingsBySeverity.get(Severity.HIGH).get(),
                    findingsBySeverity.get(Severity.MEDIUM).get(),
                    findingsBySeverity.get(Severity.LOW).get(),
                    findingsBySeverity.get(Severity.INFO).get());

        } catch (Exception e) {
            logger.error("Unhandled exception during scan: {}", e.getMessage());
            logger.debug("Exception details:", e);
        }

        scanEndTime = LocalDateTime.now();
        ScanResult result = new ScanResult(config.getTargetUrl(), findings);
        result.setScanStartTime(scanStartTime);
        result.setScanEndTime(scanEndTime);

        return result;
    }

    /**
     * Attempts to discover API endpoints for the target.
     *
     * @return A list of discovered endpoints
     */
    private List<EndpointInfo> discoverEndpoints() {
        return discoveryService.discoverEndpoints();
    }

    /**
     * Logs the current progress of the scan.
     */
    private void logProgress() {
        int completed = completedTasks.get();
        int total = totalTasks.get();
        double percentComplete = (double) completed / total * 100;

        logger.info("Scan progress: {}% ({}/{} tasks completed)",
                String.format("%.1f", percentComplete), completed, total);
    }

    /**
     * Creates an empty scan result when no endpoints are found.
     *
     * @return An empty scan result
     */
    private ScanResult createEmptyScanResult() {
        scanEndTime = LocalDateTime.now();
        ScanResult result = new ScanResult(config.getTargetUrl(), List.of());
        result.setScanStartTime(scanStartTime);
        result.setScanEndTime(scanEndTime);
        return result;
    }
}