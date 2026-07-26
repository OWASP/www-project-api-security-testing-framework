package org.owasp.astf.core;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.discovery.EndpointDiscoveryService;
import org.owasp.astf.core.discovery.PathTemplateResolver;
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

            // Attach base URL to all endpoints for test cases to use
            String targetUrl = config.getTargetUrl();
            for (EndpointInfo ep : endpoints) {
                if (ep.getBaseUrl() == null) {
                    ep.setBaseUrl(targetUrl);
                }
            }

            // Resolve unresolved OpenAPI path-template placeholders (e.g. /users/v1/{username})
            // to real, discovered values ONCE here, centrally, before any test case runs — rather
            // than leaving each test case to either duplicate this resolution logic itself (only
            // BrokenObjectLevelAuthorizationTestCase originally did) or send the literal,
            // unresolved placeholder on every request. That literal-placeholder request isn't
            // just untested — a raw, unencoded "{" / "}" in an HTTP request line is invalid per
            // RFC 3986, and live testing against VAmPI found its dev server doesn't error on that,
            // it hangs the connection with no response at all, burning the full timeout on every
            // test case that hits it. EndpointInfo.getFullUrl() now percent-encodes as a safety
            // net regardless, but resolving to a real value here means every test case gets to
            // exercise the actual target resource instead of a dead template string.
            //
            // No endpoint is ever dropped by this step, resolved or not — an endpoint that can't
            // be resolved is simply left as-is and still tested exactly as before, since the
            // scan's purpose is to find as many real issues as possible, not to narrow what gets
            // tested.
            List<EndpointInfo> resolvedEndpoints = new ArrayList<>(endpoints.size());
            for (EndpointInfo ep : endpoints) {
                resolvedEndpoints.add(PathTemplateResolver.resolve(ep, httpClient));
            }
            endpoints = resolvedEndpoints;

            // Get applicable test cases
            List<TestCase> testCases = testCaseRegistry.getEnabledTestCases(config);
            logger.info("Running {} test cases against {} endpoints", testCases.size(), endpoints.size());

            // Calculate total tasks for progress tracking
            totalTasks.set(endpoints.size() * testCases.size());

            // Run test cases against endpoints using virtual threads (Java 21).
            //
            // Deliberately NOT a try-with-resources here: ExecutorService.close() (the
            // try-with-resources exit path) calls shutdown() — which lets already-running
            // tasks finish on their own — and then awaits termination in up to 24-hour
            // increments, repeating until every task terminates. If a single task is stuck
            // (a bug in a test case, a blocking call that doesn't honor its timeout, ...) that
            // wait can silently outlast the orTimeout() below by hours, defeating the whole
            // point of a configured scan timeout: no report would ever get written. The
            // explicit try/finally below instead force-interrupts remaining tasks and bounds
            // the wait to a few seconds, guaranteeing scan() always returns with whatever
            // findings were collected.
            ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
            // Bounds how many test-case executions (i.e. concurrent outbound HTTP requests)
            // are in flight at once. Without this, every endpoint x test-case combination
            // fires as a fully unbounded concurrent virtual thread — e.g. 44 endpoints x 12
            // test cases = 528 simultaneous requests — which can overwhelm a target (especially
            // a locally-run, resource-constrained one) badly enough that requests stall well
            // past any per-request HTTP timeout. --threads/-t (config.getThreads()) is
            // documented as controlling concurrency but was previously never actually applied.
            int maxConcurrency = Math.max(1, config.getThreads());
            Semaphore concurrencyLimiter = new Semaphore(maxConcurrency);
            try {
                List<CompletableFuture<Void>> futures = new ArrayList<>();

                for (EndpointInfo endpoint : endpoints) {
                    for (TestCase testCase : testCases) {
                        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                            try {
                                concurrencyLimiter.acquire();
                            } catch (InterruptedException ie) {
                                Thread.currentThread().interrupt();
                                completedTasks.incrementAndGet();
                                return;
                            }
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
                                concurrencyLimiter.release();
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
            } finally {
                // Interrupt anything still running and bound the shutdown wait — see comment
                // above. A scan must always finish and produce a report, never hang forever.
                executor.shutdownNow();
                try {
                    if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                        logger.warn("{} of {} tasks did not terminate within 10s of shutdown; " +
                                        "proceeding with the {} finding(s) collected so far.",
                                totalTasks.get() - completedTasks.get(), totalTasks.get(), findings.size());
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
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