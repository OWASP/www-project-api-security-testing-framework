package org.owasp.astf.integrations.detection;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.providers.github.GitHubActionsEnvironmentProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;

/**
 * Detects the current CI/CD environment.
 * This class uses a combination of environment variables, file system markers,
 * and other techniques to identify the CI/CD platform where the tool is running.
 */
public class CIEnvironmentDetector {
    private static final Logger logger = LogManager.getLogger(CIEnvironmentDetector.class);

    // List of detector implementations loaded via SPI
    private final List<CIEnvironmentProvider> providers;

    /**
     * Creates a new CI environment detector.
     */
    public CIEnvironmentDetector() {
        this.providers = new ArrayList<>();
        loadProvidersFromSPI();
    }

    /**
     * Detects the current CI/CD environment.
     *
     * @return An Optional containing the detected environment, or empty if none was detected
     */
    public Optional<CIEnvironment> detect() {
        logger.debug("Detecting CI environment...");

        for (CIEnvironmentProvider provider : providers) {
            if (provider.isApplicable()) {
                logger.info("Detected CI environment: {}", provider.getName());
                return Optional.of(provider.getEnvironment());
            }
        }

        logger.info("No CI environment detected, using local environment");
        return Optional.empty();
    }

    /**
     * Loads CI environment providers using the Service Provider Interface.
     */
    private void loadProvidersFromSPI() {
        ServiceLoader<CIEnvironmentProvider> serviceLoader = ServiceLoader.load(CIEnvironmentProvider.class);
        for (CIEnvironmentProvider provider : serviceLoader) {
            providers.add(provider);
            logger.debug("Loaded CI environment provider: {}", provider.getName());
        }

        // Add built-in providers if they weren't loaded via SPI
        addBuiltInProviders();

        logger.debug("Loaded {} CI environment providers", providers.size());
    }

    /**
     * Adds built-in CI environment providers.
     * This ensures that the detector works even if SPI loading fails.
     */
    private void addBuiltInProviders() {
        List<String> existingProviderNames = providers.stream()
                .map(CIEnvironmentProvider::getName)
                .toList();

        // Add GitHub Actions provider if not already loaded
        if (!existingProviderNames.contains("GitHub Actions")) {
            providers.add(new GitHubActionsEnvironmentProvider());
        }

        /*
        // Add Jenkins provider if not already loaded
        if (!existingProviderNames.contains("Jenkins")) {
            providers.add(new JenkinsEnvironmentProvider());
        }

        // Add GitLab CI provider if not already loaded
        if (!existingProviderNames.contains("GitLab CI")) {
            providers.add(new GitLabCIEnvironmentProvider());
        }

        // Add Azure DevOps provider if not already loaded
        if (!existingProviderNames.contains("Azure DevOps")) {
            providers.add(new AzureDevOpsEnvironmentProvider());
        }

        // Add CircleCI provider if not already loaded
        if (!existingProviderNames.contains("CircleCI")) {
            providers.add(new CircleCIEnvironmentProvider());
        }

        // Add Travis CI provider if not already loaded
        if (!existingProviderNames.contains("Travis CI")) {
            providers.add(new TravisCIEnvironmentProvider());
        }
        */

    }

    /**
     * Registers a custom CI environment provider.
     *
     * @param provider The provider to register
     */
    public void registerProvider(CIEnvironmentProvider provider) {
        providers.add(provider);
        logger.debug("Registered custom CI environment provider: {}", provider.getName());
    }

    /**
     * Gets all registered CI environment providers.
     *
     * @return The list of providers
     */
    public List<CIEnvironmentProvider> getProviders() {
        return new ArrayList<>(providers);
    }
}