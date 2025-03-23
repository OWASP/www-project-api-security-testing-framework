package org.owasp.astf.integrations;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.core.CIIntegration;
import org.owasp.astf.integrations.detection.CIEnvironmentDetector;
import org.owasp.astf.integrations.providers.github.GitHubActionsIntegration;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;

/**
 * Manages CI/CD integrations for the ASTF.
 * This class provides a central point for detecting, initializing, and
 * using CI/CD integrations in the security testing framework.
 */
public class IntegrationManager {
    private static final Logger logger = LogManager.getLogger(IntegrationManager.class);

    private final CIEnvironmentDetector environmentDetector;
    private final Map<String, CIIntegration> availableIntegrations;
    private CIIntegration activeIntegration;

    /**
     * Creates a new integration manager.
     */
    public IntegrationManager() {
        this.environmentDetector = new CIEnvironmentDetector();
        this.availableIntegrations = new HashMap<>();
        loadIntegrations();
    }

    /**
     * Detects and initializes the appropriate CI/CD integration.
     *
     * @return true if an integration was successfully initialized, false otherwise
     */
    public boolean initialize() {
        logger.info("Initializing CI/CD integration");

        // Detect the CI environment
        Optional<CIEnvironment> detectedEnvironment = environmentDetector.detect();

        if (detectedEnvironment.isPresent()) {
            CIEnvironment environment = detectedEnvironment.get();
            logger.info("Detected CI environment: {}", environment.getPlatformName());

            // Find a matching integration
            Optional<CIIntegration> integration = findIntegration(environment.getPlatformName());
            if (integration.isPresent()) {
                activeIntegration = integration.get();
                logger.info("Using integration: {}", activeIntegration.getName());

                // Initialize the integration
                boolean initialized = activeIntegration.initialize();
                if (!initialized) {
                    logger.error("Failed to initialize {} integration", activeIntegration.getName());
                    activeIntegration = null;
                    return false;
                }

                logger.info("CI/CD integration initialized successfully");
                return true;
            } else {
                logger.warn("No integration available for {}", environment.getPlatformName());
            }
        } else {
            logger.info("No CI environment detected, running in standalone mode");
        }

        return false;
    }

    /**
     * Configures a scan based on the active CI/CD integration.
     *
     * @param userConfig Optional user-provided configuration
     * @return The configured scan configuration
     */
    public ScanConfig configureScan(Optional<ScanConfig> userConfig) {
        if (activeIntegration != null) {
            logger.info("Configuring scan using {} integration", activeIntegration.getName());
            return activeIntegration.configureScan(userConfig);
        }

        logger.info("No active integration, using user configuration directly");
        return userConfig.orElse(new ScanConfig());
    }

    /**
     * Processes scan results using the active CI/CD integration.
     *
     * @param results The scan results to process
     * @return true if processing was successful, false otherwise
     */
    public boolean processResults(ScanResult results) {
        if (activeIntegration != null) {
            logger.info("Processing results using {} integration", activeIntegration.getName());
            return activeIntegration.processResults(results);
        }

        logger.info("No active integration, skipping result processing");
        return true;
    }

    /**
     * Determines if the build should fail based on the scan results.
     *
     * @param results The scan results
     * @return true if the build should fail, false otherwise
     */
    public boolean shouldFailBuild(ScanResult results) {
        if (activeIntegration != null) {
            logger.info("Determining build status using {} integration", activeIntegration.getName());
            return activeIntegration.shouldFailBuild(results);
        }

        logger.info("No active integration, using default build failure criteria");

        // Default implementation - fail on any high or critical findings
        return results.getFindings().stream()
                .anyMatch(finding ->
                        finding.getSeverity() == org.owasp.astf.core.result.Severity.CRITICAL ||
                                finding.getSeverity() == org.owasp.astf.core.result.Severity.HIGH);
    }

    /**
     * Gets the active CI/CD integration.
     *
     * @return An Optional containing the active integration, or empty if none is active
     */
    public Optional<CIIntegration> getActiveIntegration() {
        return Optional.ofNullable(activeIntegration);
    }

    /**
     * Finds an integration for the specified platform.
     *
     * @param platformName The name of the CI/CD platform
     * @return An Optional containing the integration, or empty if none was found
     */
    public Optional<CIIntegration> findIntegration(String platformName) {
        return Optional.ofNullable(availableIntegrations.get(platformName));
    }

    /**
     * Registers a CI/CD integration.
     *
     * @param integration The integration to register
     */
    public void registerIntegration(CIIntegration integration) {
        availableIntegrations.put(integration.getName(), integration);
        logger.debug("Registered integration: {}", integration.getName());
    }

    /**
     * Gets all available CI/CD integrations.
     *
     * @return A map of integration names to integrations
     */
    public Map<String, CIIntegration> getAvailableIntegrations() {
        return new HashMap<>(availableIntegrations);
    }

    /**
     * Loads available CI/CD integrations.
     * This uses both built-in integrations and those loaded via SPI.
     */
    private void loadIntegrations() {
        // Load built-in integrations
        loadBuiltInIntegrations();

        // Load integrations via SPI
        ServiceLoader<CIIntegration> serviceLoader = ServiceLoader.load(CIIntegration.class);
        for (CIIntegration integration : serviceLoader) {
            registerIntegration(integration);
        }

        logger.info("Loaded {} CI/CD integrations", availableIntegrations.size());
    }

    /**
     * Loads built-in CI/CD integrations.
     */
    private void loadBuiltInIntegrations() {
        // Register GitHub Actions integration
        registerIntegration(new GitHubActionsIntegration());

        // Additional integrations can be added as they are implemented
        // Examples:
        // registerIntegration(new JenkinsIntegration());
        // registerIntegration(new GitLabCIIntegration());
        // registerIntegration(new AzureDevOpsIntegration());
    }

    /**
     * Closes all resources used by the integration manager and its integrations.
     */
    public void close() {
        if (activeIntegration != null) {
            logger.debug("Cleaning up active integration: {}", activeIntegration.getName());
            activeIntegration.cleanup();
            activeIntegration = null;
        }

        logger.debug("Integration manager closed");
    }

    /**
     * Sets a specific integration as active, bypassing auto-detection.
     * This is useful for testing or when manual selection is required.
     *
     * @param integrationName The name of the integration to activate
     * @return true if the integration was found and initialized, false otherwise
     */
    public boolean setActiveIntegration(String integrationName) {
        Optional<CIIntegration> integration = findIntegration(integrationName);
        if (integration.isPresent()) {
            CIIntegration newIntegration = integration.get();

            // Clean up previous integration if needed
            if (activeIntegration != null) {
                activeIntegration.cleanup();
            }

            // Set and initialize the new integration
            activeIntegration = newIntegration;
            boolean initialized = activeIntegration.initialize();

            if (!initialized) {
                logger.error("Failed to initialize manually selected integration: {}", integrationName);
                activeIntegration = null;
                return false;
            }

            logger.info("Manually set active integration: {}", integrationName);
            return true;
        }

        logger.warn("Integration not found: {}", integrationName);
        return false;
    }

    /**
     * Gets the detected CI/CD environment, if any.
     *
     * @return An Optional containing the detected environment, or empty if none was detected
     */
    public Optional<CIEnvironment> getDetectedEnvironment() {
        return environmentDetector.detect();
    }
}