package org.owasp.astf.integration;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;

/**
 * Manages the lifecycle of all registered {@link Integration} implementations.
 *
 * <p>On construction the manager pre-registers built-in integrations. Callers may
 * add additional integrations via {@link #registerIntegration(Integration)}. Only
 * integrations for which {@link Integration#isAvailable()} returns {@code true} are
 * initialized or asked to process results.
 */
public class IntegrationManager {
    private static final Logger logger = LogManager.getLogger(IntegrationManager.class);

    private final List<Integration> integrations = new ArrayList<>();

    /** Creates a manager pre-loaded with all built-in integrations. */
    public IntegrationManager() {
        registerIntegration(new GitHubActionsIntegration());
    }

    /**
     * Registers an additional integration.
     *
     * @param integration the integration to add
     */
    public void registerIntegration(Integration integration) {
        integrations.add(integration);
        logger.debug("Registered integration: {}", integration.getName());
    }

    /** Returns an unmodifiable snapshot of all registered integrations (available or not). */
    public List<Integration> getRegisteredIntegrations() {
        return List.copyOf(integrations);
    }

    /** Returns only the integrations whose {@link Integration#isAvailable()} returns {@code true}. */
    public List<Integration> getAvailableIntegrations() {
        return integrations.stream().filter(Integration::isAvailable).toList();
    }

    /**
     * Initializes every available integration with the given configuration.
     *
     * @param config the scan configuration
     */
    public void initializeAll(ScanConfig config) {
        for (Integration integration : getAvailableIntegrations()) {
            try {
                integration.initialize(config);
                logger.info("Initialized integration: {}", integration.getName());
            } catch (Exception e) {
                logger.warn("Failed to initialize integration '{}': {}", integration.getName(), e.getMessage());
            }
        }
    }

    /**
     * Passes the completed scan result to every available integration for post-processing.
     *
     * @param result the completed scan result
     */
    public void processResults(ScanResult result) {
        for (Integration integration : getAvailableIntegrations()) {
            try {
                integration.processResults(result);
                logger.info("Results processed by integration: {}", integration.getName());
            } catch (Exception e) {
                logger.warn("Integration '{}' failed to process results: {}", integration.getName(), e.getMessage());
            }
        }
    }
}
