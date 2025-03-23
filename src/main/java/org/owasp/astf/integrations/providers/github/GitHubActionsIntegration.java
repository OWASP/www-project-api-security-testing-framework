package org.owasp.astf.integrations.providers.github;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.core.CIIntegration;
import org.owasp.astf.integrations.core.ConfigAdapter;
import org.owasp.astf.integrations.core.ResultProcessor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Integration with GitHub Actions.
 * This class implements the CI integration for GitHub Actions,
 * providing GitHub-specific functionality for security scanning.
 */
public class GitHubActionsIntegration implements CIIntegration {
    private static final Logger logger = LogManager.getLogger(GitHubActionsIntegration.class);

    private final GitHubActionsEnvironment environment;
    private final GitHubActionsConfigAdapter configAdapter;
    private final GitHubActionsResultProcessor resultProcessor;
    private final Map<String, String> options;

    /**
     * Creates a new GitHub Actions integration.
     */
    public GitHubActionsIntegration() {
        this.environment = new GitHubActionsEnvironment();
        this.configAdapter = new GitHubActionsConfigAdapter();
        this.resultProcessor = new GitHubActionsResultProcessor();
        this.options = new HashMap<>();
    }

    @Override
    public boolean initialize() {
        logger.info("Initializing GitHub Actions integration");

        // Set default options
        options.put("create-annotations", "true");
        options.put("upload-sarif", "true");
        options.put("publish-summary", "true");

        // Check if running in GitHub Actions
        if (!environment.getEnvironmentVariable("GITHUB_ACTIONS").isPresent() ||
                !environment.getEnvironmentVariable("GITHUB_TOKEN").isPresent()) {
            logger.warn("Not running in GitHub Actions or missing GITHUB_TOKEN");
            return false;
        }

        // Create output directory if it doesn't exist
        try {
            Path outputDir = Paths.get(environment.getWorkspaceDirectory(), "scan-results");
            if (!Files.exists(outputDir)) {
                Files.createDirectories(outputDir);
            }
        } catch (IOException e) {
            logger.error("Failed to create output directory: {}", e.getMessage());
            return false;
        }

        logger.info("GitHub Actions integration initialized successfully");
        return true;
    }

    @Override
    public CIEnvironment getEnvironment() {
        return environment;
    }

    @Override
    public ScanConfig configureScan(Optional<ScanConfig> userConfig) {
        logger.info("Configuring scan for GitHub Actions");

        // Start with a default configuration
        ScanConfig config = configAdapter.createDefaultConfig(environment);

        // Look for a configuration file
        File configFile = new File(environment.getWorkspaceDirectory(), configAdapter.getConfigFileName());
        if (configFile.exists()) {
            logger.info("Loading configuration from file: {}", configFile.getAbsolutePath());
            Optional<ScanConfig> fileConfig = configAdapter.loadFromFile(configFile);
            if (fileConfig.isPresent()) {
                config = configAdapter.mergeConfigs(config, fileConfig.get());
            }
        }

        // Load configuration from environment variables
        Optional<ScanConfig> envConfig = configAdapter.loadFromEnvironment(environment);
        if (envConfig.isPresent()) {
            config = configAdapter.mergeConfigs(config, envConfig.get());
        }

        // If user provided a config, apply it last (highest priority)
        if (userConfig.isPresent()) {
            config = configAdapter.mergeConfigs(config, userConfig.get());
        }

        // Adapt the configuration for GitHub Actions
        config = configAdapter.adapt(config, environment);

        // Validate the configuration
        Map<String, String> validationIssues = configAdapter.validateConfig(config);
        if (!validationIssues.isEmpty()) {
            logger.warn("Configuration validation issues:");
            validationIssues.forEach((key, value) -> logger.warn("  {}: {}", key, value));
        }

        return config;
    }

    @Override
    public ScanResult executeScan(ScanConfig config) {
        logger.info("Executing scan with GitHub Actions integration");

        // Create and configure the scanner
        Scanner scanner = new Scanner(config);

        // Execute the scan
        logger.info("Starting scan for target: {}", config.getTargetUrl());
        ScanResult results = scanner.scan();
        logger.info("Scan completed. Found {} findings", results.getTotalFindingsCount());

        return results;
    }

    @Override
    public boolean processResults(ScanResult results) {
        logger.info("Processing scan results for GitHub Actions");

        // Process the results
        boolean processed = resultProcessor.processResults(results, environment);
        if (!processed) {
            logger.error("Failed to process scan results");
            return false;
        }

        // Publish the results
        boolean published = resultProcessor.publishResults(results, environment);
        if (!published) {
            logger.error("Failed to publish scan results");
            return false;
        }

        logger.info("Scan results processed and published successfully");
        return true;
    }

    @Override
    public boolean shouldFailBuild(ScanResult results) {
        // Define thresholds for build failure
        Map<Severity, Integer> thresholds = new HashMap<>();
        thresholds.put(Severity.CRITICAL, 0);  // Any critical finding fails the build
        thresholds.put(Severity.HIGH, 0);      // Any high finding fails the build

        // Check if environment variables override the default thresholds
        environment.getEnvironmentVariable("ASTF_THRESHOLD_CRITICAL")
                .map(Integer::parseInt)
                .ifPresent(threshold -> thresholds.put(Severity.CRITICAL, threshold));

        environment.getEnvironmentVariable("ASTF_THRESHOLD_HIGH")
                .map(Integer::parseInt)
                .ifPresent(threshold -> thresholds.put(Severity.HIGH, threshold));

        environment.getEnvironmentVariable("ASTF_THRESHOLD_MEDIUM")
                .map(Integer::parseInt)
                .ifPresent(threshold -> thresholds.put(Severity.MEDIUM, threshold));

        environment.getEnvironmentVariable("ASTF_THRESHOLD_LOW")
                .map(Integer::parseInt)
                .ifPresent(threshold -> thresholds.put(Severity.LOW, threshold));

        // Determine if the build should fail
        boolean shouldFail = resultProcessor.shouldFailBuild(results, thresholds);

        // Log the decision
        if (shouldFail) {
            logger.info("Build will fail due to security findings exceeding thresholds");
        } else {
            logger.info("Security findings are within acceptable thresholds");
        }

        return shouldFail;
    }

    @Override
    public ResultProcessor getResultProcessor() {
        return resultProcessor;
    }

    @Override
    public ConfigAdapter getConfigAdapter() {
        return configAdapter;
    }

    @Override
    public Map<String, String> getOptions() {
        return new HashMap<>(options);
    }

    @Override
    public void setOptions(Map<String, String> options) {
        this.options.clear();
        this.options.putAll(options);
    }

    @Override
    public String getName() {
        return "GitHub Actions";
    }

    @Override
    public void cleanup() {
        logger.info("Cleaning up GitHub Actions integration resources");
        // No resources to clean up
    }
}