package org.owasp.astf.integration;

import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;

/**
 * Interface for CI/CD and external tool integrations.
 * Implementations can hook into the scan lifecycle to adapt output,
 * emit platform-specific annotations, or push results to external systems.
 */
public interface Integration {

    /** Human-readable name used in logs and diagnostics. */
    String getName();

    /**
     * Returns {@code true} when this integration's execution environment is detected.
     * Implementations should check environment variables or system properties.
     */
    boolean isAvailable();

    /**
     * Called once before scanning begins.
     * Implementations may adapt the configuration (e.g., switch to SARIF output).
     *
     * @param config mutable scan configuration
     */
    void initialize(ScanConfig config);

    /**
     * Called after the scan completes with the aggregated results.
     *
     * @param result the completed scan result
     */
    void processResults(ScanResult result);
}
