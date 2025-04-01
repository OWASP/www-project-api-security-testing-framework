package org.owasp.astf.integrations.providers.github;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.core.ConfigAdapter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration adapter for GitHub Actions.
 * This class adapts scan configurations for GitHub Actions environments.
 */
public class GitHubActionsConfigAdapter implements ConfigAdapter {
    private static final Logger logger = LogManager.getLogger(GitHubActionsConfigAdapter.class);
    private static final String CONFIG_FILE_NAME = "astf-config.json";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public ScanConfig adapt(ScanConfig config, CIEnvironment environment) {
        logger.debug("Adapting configuration for GitHub Actions");

        // Clone the configuration to avoid modifying the original
        ScanConfig adaptedConfig = new ScanConfig();

        // Copy all properties from the original config
        adaptedConfig.setTargetUrl(config.getTargetUrl());
        adaptedConfig.setHeaders(new HashMap<>(config.getHeaders()));
        adaptedConfig.setEndpoints(new ArrayList<>(config.getEndpoints()));
        adaptedConfig.setThreads(config.getThreads());
        adaptedConfig.setTimeoutMinutes(config.getTimeoutMinutes());
        adaptedConfig.setDiscoveryEnabled(config.isDiscoveryEnabled());
        adaptedConfig.setEnabledTestCaseIds(new ArrayList<>(config.getEnabledTestCaseIds()));
        adaptedConfig.setDisabledTestCaseIds(new ArrayList<>(config.getDisabledTestCaseIds()));
        adaptedConfig.setOutputFormat(config.getOutputFormat());
        adaptedConfig.setOutputFile(config.getOutputFile());
        adaptedConfig.setVerbose(config.isVerbose());

        // Check if we're in a pull request
        if (environment instanceof GitHubActionsEnvironment) {
            GitHubActionsEnvironment ghEnv = (GitHubActionsEnvironment) environment;
            if (ghEnv.isPullRequest()) {
                // For pull requests, we might want to adjust certain settings
                // for example, limit the scan scope or increase verbosity
                logger.info("Adapting configuration for pull request #{}", ghEnv.getPullRequestId().orElse("unknown"));

                // Example: Set output file to include PR number
                String originalOutputFile = adaptedConfig.getOutputFile();
                if (originalOutputFile != null && !originalOutputFile.isEmpty()) {
                    String prNumber = ghEnv.getPullRequestId().orElse("unknown");
                    String newOutputFile = originalOutputFile.replace(".json", "-pr" + prNumber + ".json");
                    adaptedConfig.setOutputFile(newOutputFile);
                }

                // If this is a forked repository PR, we might want to limit certain capabilities
                if (ghEnv.isForkedRepository()) {
                    logger.info("Adapting configuration for forked repository pull request");

                    // Limit the scope for security reasons in forked repos
                    adaptedConfig.setDiscoveryEnabled(false);

                    // Clear any custom endpoints that might have been provided
                    // and add only safe endpoints for testing
                    adaptedConfig.setEndpoints(new ArrayList<>());

                    // Add only specific endpoints for public PRs
                    adaptedConfig.addEndpoint(new EndpointInfo("/api/public", "GET"));
                    adaptedConfig.addEndpoint(new EndpointInfo("/api/v1/public", "GET"));
                }
            }
        }

        // Add GitHub token to authorization header if not already set
        if (!config.getHeaders().containsKey("Authorization")) {
            environment.getEnvironmentVariable("GITHUB_TOKEN").ifPresent(token -> {
                adaptedConfig.addHeader("Authorization", "Bearer " + token);
            });
        }

        // Set default output file if not specified
        if (adaptedConfig.getOutputFile() == null || adaptedConfig.getOutputFile().isEmpty()) {
            String outputFile = Paths.get(environment.getWorkspaceDirectory(), "scan-results", "scan-result.json").toString();
            adaptedConfig.setOutputFile(outputFile);
        }

        return adaptedConfig;
    }

    @Override
    public Optional<ScanConfig> loadFromFile(File configFile) {
        if (!configFile.exists() || !configFile.isFile()) {
            logger.warn("Configuration file does not exist: {}", configFile.getAbsolutePath());
            return Optional.empty();
        }

        try {
            JsonNode rootNode = objectMapper.readTree(configFile);
            return Optional.of(parseConfig(rootNode));
        } catch (IOException e) {
            logger.error("Failed to read configuration file: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<ScanConfig> loadFromEnvironment(CIEnvironment environment) {
        logger.debug("Loading configuration from environment variables");

        ScanConfig config = new ScanConfig();
        boolean foundConfig = false;

        // Target URL
        Optional<String> targetUrl = environment.getEnvironmentVariable("ASTF_TARGET_URL");
        if (targetUrl.isPresent()) {
            config.setTargetUrl(targetUrl.get());
            foundConfig = true;
        }

        // Headers
        Optional<String> authHeader = environment.getEnvironmentVariable("ASTF_AUTH_HEADER");
        if (authHeader.isPresent()) {
            config.addHeader("Authorization", authHeader.get());
            foundConfig = true;
        }

        // Threads
        Optional<String> threads = environment.getEnvironmentVariable("ASTF_THREADS");
        if (threads.isPresent()) {
            try {
                config.setThreads(Integer.parseInt(threads.get()));
                foundConfig = true;
            } catch (NumberFormatException e) {
                logger.warn("Invalid thread count: {}", threads.get());
            }
        }

        // Timeout
        Optional<String> timeout = environment.getEnvironmentVariable("ASTF_TIMEOUT");
        if (timeout.isPresent()) {
            try {
                config.setTimeoutMinutes(Integer.parseInt(timeout.get()));
                foundConfig = true;
            } catch (NumberFormatException e) {
                logger.warn("Invalid timeout: {}", timeout.get());
            }
        }

        // Discovery enabled
        Optional<String> discovery = environment.getEnvironmentVariable("ASTF_DISCOVERY_ENABLED");
        if (discovery.isPresent()) {
            config.setDiscoveryEnabled(Boolean.parseBoolean(discovery.get()));
            foundConfig = true;
        }

        // Output format
        Optional<String> outputFormat = environment.getEnvironmentVariable("ASTF_OUTPUT_FORMAT");
        if (outputFormat.isPresent()) {
            try {
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(outputFormat.get().toUpperCase()));
                foundConfig = true;
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}", outputFormat.get());
            }
        }

        // Output file
        Optional<String> outputFile = environment.getEnvironmentVariable("ASTF_OUTPUT_FILE");
        if (outputFile.isPresent()) {
            config.setOutputFile(outputFile.get());
            foundConfig = true;
        }

        // Verbose
        Optional<String> verbose = environment.getEnvironmentVariable("ASTF_VERBOSE");
        if (verbose.isPresent()) {
            config.setVerbose(Boolean.parseBoolean(verbose.get()));
            foundConfig = true;
        }

        // Enabled test cases
        Optional<String> enabledTests = environment.getEnvironmentVariable("ASTF_ENABLED_TESTS");
        if (enabledTests.isPresent()) {
            List<String> testIds = new ArrayList<>();
            for (String id : enabledTests.get().split(",")) {
                testIds.add(id.trim());
            }
            config.setEnabledTestCaseIds(testIds);
            foundConfig = true;
        }

        // Disabled test cases
        Optional<String> disabledTests = environment.getEnvironmentVariable("ASTF_DISABLED_TESTS");
        if (disabledTests.isPresent()) {
            List<String> testIds = new ArrayList<>();
            for (String id : disabledTests.get().split(",")) {
                testIds.add(id.trim());
            }
            config.setDisabledTestCaseIds(testIds);
            foundConfig = true;
        }

        return foundConfig ? Optional.of(config) : Optional.empty();
    }

    @Override
    public ScanConfig createDefaultConfig(CIEnvironment environment) {
        logger.debug("Creating default configuration for GitHub Actions");

        ScanConfig config = new ScanConfig();

        // Set default target URL (try to guess from repository)
        if (environment instanceof GitHubActionsEnvironment) {
            GitHubActionsEnvironment ghEnv = (GitHubActionsEnvironment) environment;
            String repoName = ghEnv.getRepositoryName();
            if (repoName.contains("/")) {
                String[] parts = repoName.split("/");
                String orgName = parts[0];
                String projectName = parts[1];

                // Try to guess a reasonable default URL
                // This is just an example and might not be accurate
                config.setTargetUrl("https://" + orgName + ".github.io/" + projectName + "/api");
            }
        }

        // Default settings
        config.setThreads(10);
        config.setTimeoutMinutes(30);
        config.setDiscoveryEnabled(true);
        config.setOutputFormat(ScanConfig.OutputFormat.JSON);
        config.setVerbose(true);

        // Default output location
        String outputFile = Paths.get(environment.getWorkspaceDirectory(), "scan-results", "scan-result.json").toString();
        config.setOutputFile(outputFile);

        return config;
    }

    @Override
    public Map<String, String> validateConfig(ScanConfig config) {
        Map<String, String> issues = new HashMap<>();

        // Validate target URL
        if (config.getTargetUrl() == null || config.getTargetUrl().isEmpty()) {
            issues.put("targetUrl", "Target URL is required");
        }

        // Validate threads
        if (config.getThreads() <= 0) {
            issues.put("threads", "Thread count must be positive");
        }

        // Validate timeout
        if (config.getTimeoutMinutes() <= 0) {
            issues.put("timeoutMinutes", "Timeout must be positive");
        }

        // Validate output file
        if (config.getOutputFile() != null && !config.getOutputFile().isEmpty()) {
            File outputFile = new File(config.getOutputFile());
            File parentDir = outputFile.getParentFile();
            if (parentDir != null && !parentDir.exists() && !parentDir.mkdirs()) {
                issues.put("outputFile", "Cannot create parent directories for output file");
            }
        }

        return issues;
    }

    @Override
    public ScanConfig sanitizeConfig(ScanConfig config) {
        // Clone the configuration to avoid modifying the original
        ScanConfig sanitizedConfig = new ScanConfig();

        // Copy all properties from the original config
        sanitizedConfig.setTargetUrl(config.getTargetUrl());
        sanitizedConfig.setThreads(config.getThreads());
        sanitizedConfig.setTimeoutMinutes(config.getTimeoutMinutes());
        sanitizedConfig.setDiscoveryEnabled(config.isDiscoveryEnabled());
        sanitizedConfig.setEnabledTestCaseIds(new ArrayList<>(config.getEnabledTestCaseIds()));
        sanitizedConfig.setDisabledTestCaseIds(new ArrayList<>(config.getDisabledTestCaseIds()));
        sanitizedConfig.setOutputFormat(config.getOutputFormat());
        sanitizedConfig.setOutputFile(config.getOutputFile());
        sanitizedConfig.setVerbose(config.isVerbose());
        sanitizedConfig.setEndpoints(new ArrayList<>(config.getEndpoints()));

        // Sanitize headers (remove sensitive information)
        Map<String, String> sanitizedHeaders = new HashMap<>();
        for (Map.Entry<String, String> entry : config.getHeaders().entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            // Mask sensitive headers
            if (key.equalsIgnoreCase("Authorization") ||
                    key.equalsIgnoreCase("Cookie") ||
                    key.toLowerCase().contains("key") ||
                    key.toLowerCase().contains("token") ||
                    key.toLowerCase().contains("secret")) {
                value = "********";
            }

            sanitizedHeaders.put(key, value);
        }
        sanitizedConfig.setHeaders(sanitizedHeaders);

        return sanitizedConfig;
    }

    @Override
    public ScanConfig mergeConfigs(ScanConfig... configs) {
        if (configs.length == 0) {
            return new ScanConfig();
        }

        if (configs.length == 1) {
            return configs[0];
        }

        // Start with the first config
        ScanConfig mergedConfig = configs[0];

        // Merge with subsequent configs
        for (int i = 1; i < configs.length; i++) {
            ScanConfig config = configs[i];

            // Only override if the new value is non-null or non-empty
            if (config.getTargetUrl() != null && !config.getTargetUrl().isEmpty()) {
                mergedConfig.setTargetUrl(config.getTargetUrl());
            }

            // Merge headers
            for (Map.Entry<String, String> entry : config.getHeaders().entrySet()) {
                mergedConfig.addHeader(entry.getKey(), entry.getValue());
            }

            // Merge endpoints (add all unique endpoints)
            for (EndpointInfo endpoint : config.getEndpoints()) {
                if (!containsEndpoint(mergedConfig.getEndpoints(), endpoint)) {
                    mergedConfig.addEndpoint(endpoint);
                }
            }

            // Override numeric values if they are specified
            if (config.getThreads() > 0) {
                mergedConfig.setThreads(config.getThreads());
            }

            if (config.getTimeoutMinutes() > 0) {
                mergedConfig.setTimeoutMinutes(config.getTimeoutMinutes());
            }

            // Override boolean values
            mergedConfig.setDiscoveryEnabled(config.isDiscoveryEnabled());
            mergedConfig.setVerbose(config.isVerbose());

            // Merge test case IDs
            if (!config.getEnabledTestCaseIds().isEmpty()) {
                mergedConfig.setEnabledTestCaseIds(new ArrayList<>(config.getEnabledTestCaseIds()));
            }

            if (!config.getDisabledTestCaseIds().isEmpty()) {
                mergedConfig.setDisabledTestCaseIds(new ArrayList<>(config.getDisabledTestCaseIds()));
            }

            // Override output format
            if (config.getOutputFormat() != null) {
                mergedConfig.setOutputFormat(config.getOutputFormat());
            }

            // Override output file
            if (config.getOutputFile() != null && !config.getOutputFile().isEmpty()) {
                mergedConfig.setOutputFile(config.getOutputFile());
            }
        }

        return mergedConfig;
    }

    @Override
    public String getConfigFileName() {
        return CONFIG_FILE_NAME;
    }

    @Override
    public ScanConfig convertFromPlatformFormat(Map<String, Object> platformConfig) {
        ScanConfig config = new ScanConfig();

        // Extract configuration from the GitHub Actions workflow YAML format
        Object targetUrl = platformConfig.get("target-url");
        if (targetUrl != null) {
            config.setTargetUrl(targetUrl.toString());
        }

        Object authHeader = platformConfig.get("auth-header");
        if (authHeader != null) {
            config.addHeader("Authorization", authHeader.toString());
        }

        Object threads = platformConfig.get("threads");
        if (threads != null) {
            try {
                config.setThreads(Integer.parseInt(threads.toString()));
            } catch (NumberFormatException e) {
                logger.warn("Invalid thread count: {}", threads);
            }
        }

        Object timeout = platformConfig.get("timeout");
        if (timeout != null) {
            try {
                config.setTimeoutMinutes(Integer.parseInt(timeout.toString()));
            } catch (NumberFormatException e) {
                logger.warn("Invalid timeout: {}", timeout);
            }
        }

        Object discovery = platformConfig.get("discovery-enabled");
        if (discovery != null) {
            config.setDiscoveryEnabled(Boolean.parseBoolean(discovery.toString()));
        }

        Object outputFormat = platformConfig.get("output-format");
        if (outputFormat != null) {
            try {
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(outputFormat.toString().toUpperCase()));
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}", outputFormat);
            }
        }

        Object outputFile = platformConfig.get("output-file");
        if (outputFile != null) {
            config.setOutputFile(outputFile.toString());
        }

        Object verbose = platformConfig.get("verbose");
        if (verbose != null) {
            config.setVerbose(Boolean.parseBoolean(verbose.toString()));
        }

        Object enabledTests = platformConfig.get("enabled-tests");
        if (enabledTests != null) {
            List<String> testIds = new ArrayList<>();
            for (String id : enabledTests.toString().split(",")) {
                testIds.add(id.trim());
            }
            config.setEnabledTestCaseIds(testIds);
        }

        Object disabledTests = platformConfig.get("disabled-tests");
        if (disabledTests != null) {
            List<String> testIds = new ArrayList<>();
            for (String id : disabledTests.toString().split(",")) {
                testIds.add(id.trim());
            }
            config.setDisabledTestCaseIds(testIds);
        }

        return config;
    }

    /**
     * Parses a scan configuration from a JSON node.
     *
     * @param rootNode The JSON node to parse
     * @return The parsed scan configuration
     */
    private ScanConfig parseConfig(JsonNode rootNode) {
        ScanConfig config = new ScanConfig();

        // Parse basic properties
        if (rootNode.has("targetUrl")) {
            config.setTargetUrl(rootNode.get("targetUrl").asText());
        }

        if (rootNode.has("threads")) {
            config.setThreads(rootNode.get("threads").asInt());
        }

        if (rootNode.has("timeoutMinutes")) {
            config.setTimeoutMinutes(rootNode.get("timeoutMinutes").asInt());
        }

        if (rootNode.has("discoveryEnabled")) {
            config.setDiscoveryEnabled(rootNode.get("discoveryEnabled").asBoolean());
        }

        if (rootNode.has("verbose")) {
            config.setVerbose(rootNode.get("verbose").asBoolean());
        }

        if (rootNode.has("outputFile")) {
            config.setOutputFile(rootNode.get("outputFile").asText());
        }

        if (rootNode.has("outputFormat")) {
            try {
                String formatStr = rootNode.get("outputFormat").asText();
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(formatStr.toUpperCase()));
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}", rootNode.get("outputFormat").asText());
            }
        }

        // Parse headers
        if (rootNode.has("headers") && rootNode.get("headers").isObject()) {
            JsonNode headersNode = rootNode.get("headers");
            headersNode.fields().forEachRemaining(entry -> {
                config.addHeader(entry.getKey(), entry.getValue().asText());
            });
        }

        // Parse enabled test cases
        if (rootNode.has("enabledTestCaseIds") && rootNode.get("enabledTestCaseIds").isArray()) {
            List<String> enabledIds = new ArrayList<>();
            for (JsonNode idNode : rootNode.get("enabledTestCaseIds")) {
                enabledIds.add(idNode.asText());
            }
            config.setEnabledTestCaseIds(enabledIds);
        }

        // Parse disabled test cases
        if (rootNode.has("disabledTestCaseIds") && rootNode.get("disabledTestCaseIds").isArray()) {
            List<String> disabledIds = new ArrayList<>();
            for (JsonNode idNode : rootNode.get("disabledTestCaseIds")) {
                disabledIds.add(idNode.asText());
            }
            config.setDisabledTestCaseIds(disabledIds);
        }

        // Parse endpoints
        if (rootNode.has("endpoints") && rootNode.get("endpoints").isArray()) {
            for (JsonNode endpointNode : rootNode.get("endpoints")) {
                String path = endpointNode.has("path") ? endpointNode.get("path").asText() : null;
                String method = endpointNode.has("method") ? endpointNode.get("method").asText() : "GET";

                if (path != null && !path.isEmpty()) {
                    String contentType = endpointNode.has("contentType") ? endpointNode.get("contentType").asText() : "application/json";
                    String requestBody = endpointNode.has("requestBody") ? endpointNode.get("requestBody").asText() : null;
                    boolean requiresAuth = !endpointNode.has("requiresAuthentication") || endpointNode.get("requiresAuthentication").asBoolean();

                    EndpointInfo endpoint = new EndpointInfo(path, method, contentType, requestBody, requiresAuth);
                    config.addEndpoint(endpoint);
                }
            }
        }

        return config;
    }

    /**
     * Checks if a list of endpoints already contains an endpoint with the same path and method.
     *
     * @param endpoints The list of endpoints to check
     * @param endpoint The endpoint to look for
     * @return true if the list contains an equivalent endpoint, false otherwise
     */
    private boolean containsEndpoint(List<EndpointInfo> endpoints, EndpointInfo endpoint) {
        return endpoints.stream().anyMatch(e ->
                e.getPath().equals(endpoint.getPath()) &&
                        e.getMethod().equalsIgnoreCase(endpoint.getMethod())
        );
    }
}