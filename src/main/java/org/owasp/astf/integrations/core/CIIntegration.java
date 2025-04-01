package org.owasp.astf.integrations.core;

import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;

import java.util.Map;
import java.util.Optional;

/**
 * Represents an integration with a specific CI/CD platform.
 * This interface defines the contract for all CI/CD integrations,
 * ensuring consistent behavior across different platforms.
 */
public interface CIIntegration {

    /**
     * Initializes the CI/CD integration.
     *
     * @return true if initialization is successful, false otherwise
     */
    boolean initialize();

    /**
     * Gets the CI environment information.
     *
     * @return The CI environment details
     */
    CIEnvironment getEnvironment();

    /**
     * Configures the scan based on the CI environment and user configuration.
     *
     * @param userConfig Optional user-provided configuration
     * @return The configured scan configuration
     */
    ScanConfig configureScan(Optional<ScanConfig> userConfig);

    /**
     * Executes the security scan using the provided configuration.
     *
     * @param config The scan configuration
     * @return The scan results
     */
    ScanResult executeScan(ScanConfig config);

    /**
     * Processes and publishes the scan results to the CI/CD platform.
     *
     * @param results The scan results
     * @return true if results were successfully processed and published
     */
    boolean processResults(ScanResult results);

    /**
     * Determines if the build should fail based on the scan results
     * and configured thresholds.
     *
     * @param results The scan results
     * @return true if the build should fail, false otherwise
     */
    boolean shouldFailBuild(ScanResult results);

    /**
     * Gets the result processor for this integration.
     *
     * @return The result processor
     */
    ResultProcessor getResultProcessor();

    /**
     * Gets the config adapter for this integration.
     *
     * @return The config adapter
     */
    ConfigAdapter getConfigAdapter();

    /**
     * Gets the integration-specific options.
     *
     * @return A map of option names to values
     */
    Map<String, String> getOptions();

    /**
     * Sets integration-specific options.
     *
     * @param options A map of option names to values
     */
    void setOptions(Map<String, String> options);

    /**
     * Gets the name of this integration.
     *
     * @return The integration name
     */
    String getName();

    /**
     * Cleans up resources used by the integration.
     * This method should be called when the integration is no longer needed.
     */
    void cleanup();
}