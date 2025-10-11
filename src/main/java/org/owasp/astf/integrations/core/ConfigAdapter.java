package org.owasp.astf.integrations.core;

import org.owasp.astf.core.config.ScanConfig;

import java.io.File;
import java.util.Map;
import java.util.Optional;

/**
 * Adapter for configuring scans in CI/CD environments.
 * This interface defines methods for adapting scan configurations
 * to specific CI/CD platforms and environments.
 */
public interface ConfigAdapter {

    /**
     * Adapts a scan configuration for the current CI environment.
     *
     * @param config The base configuration to adapt
     * @param environment The CI environment
     * @return The adapted configuration
     */
    ScanConfig adapt(ScanConfig config, CIEnvironment environment);

    /**
     * Loads a configuration from a platform-specific configuration file.
     *
     * @param configFile The configuration file
     * @return An Optional containing the loaded configuration, or empty if the file is invalid
     */
    Optional<ScanConfig> loadFromFile(File configFile);

    /**
     * Loads a configuration from environment variables.
     *
     * @param environment The CI environment
     * @return An Optional containing the loaded configuration, or empty if required variables are missing
     */
    Optional<ScanConfig> loadFromEnvironment(CIEnvironment environment);

    /**
     * Creates a default configuration for the given CI environment.
     *
     * @param environment The CI environment
     * @return A default scan configuration
     */
    ScanConfig createDefaultConfig(CIEnvironment environment);

    /**
     * Validates a configuration for security issues and CI compatibility.
     *
     * @param config The configuration to validate
     * @return A map of validation issue keys to error messages, empty if no issues
     */
    Map<String, String> validateConfig(ScanConfig config);

    /**
     * Sanitizes sensitive information in a configuration.
     * This is used when logging or serializing configurations.
     *
     * @param config The configuration to sanitize
     * @return A sanitized copy of the configuration
     */
    ScanConfig sanitizeConfig(ScanConfig config);

    /**
     * Merges multiple configurations, with later configs overriding earlier ones.
     *
     * @param configs The configurations to merge, in order of increasing priority
     * @return The merged configuration
     */
    ScanConfig mergeConfigs(ScanConfig... configs);

    /**
     * Gets the configuration file name for this CI platform.
     *
     * @return The default configuration file name
     */
    String getConfigFileName();

    /**
     * Converts specific CI platform configuration format to ASTF format.
     *
     * @param platformConfig A map of platform-specific configuration values
     * @return The equivalent ASTF scan configuration
     */
    ScanConfig convertFromPlatformFormat(Map<String, Object> platformConfig);
}