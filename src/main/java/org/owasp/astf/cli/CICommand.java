package org.owasp.astf.cli;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.integrations.IntegrationManager;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * Command line interface for running API security scans in CI/CD environments.
 * This command automatically detects and configures CI/CD integrations.
 */
@Command(
        name = "ci",
        description = "Run API security scan in CI/CD environment",
        mixinStandardHelpOptions = true
)
public class CICommand implements Callable<Integer> {
    private static final Logger logger = LogManager.getLogger(CICommand.class);

    @Option(names = {"-c", "--config"}, description = "Path to configuration file")
    private String configFile;

    @Option(names = {"-t", "--target"}, description = "Target API URL")
    private String targetUrl;

    @Option(names = {"-a", "--auth"}, description = "Authorization header value")
    private String authHeader;

    @Option(names = {"--fail-on-findings"}, description = "Fail build on any findings (overrides CI/CD thresholds)")
    private boolean failOnFindings;

    @Option(names = {"--skip-result-upload"}, description = "Skip uploading results to CI/CD platform")
    private boolean skipResultUpload;

    @Override
    public Integer call() throws Exception {
        logger.info("Starting API security scan in CI/CD mode");

        // Create integration manager
        IntegrationManager integrationManager = new IntegrationManager();

        // Initialize CI/CD integration
        boolean ciInitialized = integrationManager.initialize();
        if (!ciInitialized) {
            logger.warn("No CI/CD integration detected or initialization failed, running in standalone mode");
        }

        // Create base configuration from command line arguments
        ScanConfig commandLineConfig = null;
        if (targetUrl != null || authHeader != null) {
            commandLineConfig = new ScanConfig();

            if (targetUrl != null) {
                commandLineConfig.setTargetUrl(targetUrl);
            }

            if (authHeader != null) {
                commandLineConfig.addHeader("Authorization", authHeader);
            }
        }

        // Configure scan based on CI/CD environment and user config
        ScanConfig scanConfig = integrationManager.configureScan(Optional.ofNullable(commandLineConfig));

        // Validate basic configuration
        if (scanConfig.getTargetUrl() == null || scanConfig.getTargetUrl().isEmpty()) {
            logger.error("No target URL specified. Use --target option or configure in CI/CD");
            return 1;
        }

        // Execute the scan
        logger.info("Executing scan against {}", scanConfig.getTargetUrl());
        Scanner scanner = new Scanner(scanConfig);
        ScanResult results = scanner.scan();

        // Process the results
        if (!skipResultUpload) {
            logger.info("Processing and publishing scan results");
            boolean processedSuccessfully = integrationManager.processResults(results);

            if (!processedSuccessfully) {
                logger.warn("Failed to process or publish results");
            }
        } else {
            logger.info("Result upload skipped as requested");
        }

        // Determine build status
        boolean shouldFail;
        if (failOnFindings) {
            // Override CI/CD thresholds and fail on any findings
            shouldFail = !results.getFindings().isEmpty();
            logger.info("Build will {} (fail-on-findings: {})",
                    shouldFail ? "fail" : "pass", failOnFindings);
        } else {
            // Use CI/CD integration or default criteria to determine build status
            shouldFail = integrationManager.shouldFailBuild(results);
            logger.info("Build will {} based on configured thresholds",
                    shouldFail ? "fail" : "pass");
        }

        // Clean up resources
        integrationManager.close();

        // Return appropriate exit code
        return shouldFail ? 1 : 0;
    }
}