package org.owasp.astf.cli;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ConfigLoader;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.reporting.ReportGenerator;
import org.owasp.astf.reporting.ReportGeneratorFactory;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Main CLI entry point for the OWASP API Security Testing Framework.
 *
 * <pre>
 * Usage: astf [OPTIONS]
 *
 * Options:
 *   -u, --url           Target API base URL (required)
 *   -c, --config        Path to configuration file (YAML/JSON/properties)
 *   -o, --output        Output file path
 *   -f, --format        Output format: JSON (default), XML, HTML, SARIF
 *   -t, --threads       Number of concurrent threads (default: 10)
 *   --token             Bearer token for authentication
 *   --api-key           API key for authentication
 *   --api-key-header    Header name for API key (default: X-API-Key)
 *   --username          Basic auth username
 *   --password          Basic auth password
 *   --header            Additional headers in Key:Value format (repeatable)
 *   --proxy             Proxy URL (e.g., http://proxy:8080)
 *   --no-discovery      Disable automatic endpoint discovery
 *   --test-cases        Comma-separated list of test case IDs to run
 *   --exclude-tests     Comma-separated list of test case IDs to skip
 *   --timeout           Scan timeout in minutes (default: 30)
 *   --verbose, -v       Enable verbose output
 *   --version, -V       Print version and exit
 *   --help, -h          Show help
 * </pre>
 */
@Command(
        name = "astf",
        mixinStandardHelpOptions = true,
        version = "OWASP API Security Testing Framework 1.0.0",
        description = "Scans API endpoints for OWASP API Security Top 10 vulnerabilities."
)
public class ASTFCli implements Callable<Integer> {
    private static final Logger logger = LogManager.getLogger(ASTFCli.class);

    @Option(names = {"-u", "--url"}, description = "Target API base URL")
    private String targetUrl;

    @Option(names = {"-c", "--config"}, description = "Path to configuration file (YAML/JSON/properties)")
    private String configFile;

    @Option(names = {"-o", "--output"}, description = "Output file path for the scan report")
    private String outputFile;

    @Option(names = {"-f", "--format"},
            description = "Output format: JSON (default), XML, HTML, SARIF",
            defaultValue = "JSON")
    private String format;

    @Option(names = {"-t", "--threads"}, description = "Number of concurrent threads (default: 10)")
    private Integer threads;

    @Option(names = {"--token"}, description = "Bearer token for authentication")
    private String bearerToken;

    @Option(names = {"--api-key"}, description = "API key for authentication")
    private String apiKey;

    @Option(names = {"--api-key-header"}, description = "Header name for API key (default: X-API-Key)")
    private String apiKeyHeader;

    @Option(names = {"--username"}, description = "Basic auth username")
    private String username;

    @Option(names = {"--password"}, description = "Basic auth password")
    private String password;

    @Option(names = {"--header"}, description = "Additional header in Key:Value format (repeatable)")
    private List<String> headers;

    @Option(names = {"--proxy"}, description = "Proxy URL (e.g., http://proxy:8080)")
    private String proxyUrl;

    @Option(names = {"--no-discovery"}, description = "Disable automatic endpoint discovery")
    private boolean noDiscovery;

    @Option(names = {"--test-cases"}, description = "Comma-separated list of test case IDs to run")
    private String enabledTestCases;

    @Option(names = {"--exclude-tests"}, description = "Comma-separated list of test case IDs to skip")
    private String disabledTestCases;

    @Option(names = {"--timeout"}, description = "Scan timeout in minutes (default: 30)")
    private Integer timeoutMinutes;

    @Option(names = {"-v", "--verbose"}, description = "Enable verbose output")
    private boolean verbose;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new ASTFCli()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        try {
            printBanner();
            ScanConfig config = buildConfig();
            validateConfig(config);

            System.out.println("Target: " + config.getTargetUrl());
            System.out.println("Format: " + config.getOutputFormat());
            System.out.println("Threads: " + config.getThreads());
            System.out.println();

            Scanner scanner = new Scanner(config);
            ScanResult result = scanner.scan();

            printResults(result);
            writeReport(result, config);

            // Exit code: 0 = no findings, 1 = findings found, 2 = error
            return result.getTotalFindingsCount() > 0 ? 1 : 0;

        } catch (IllegalArgumentException e) {
            System.err.println("Configuration error: " + e.getMessage());
            return 2;
        } catch (Exception e) {
            logger.error("Scan failed: {}", e.getMessage(), e);
            System.err.println("Scan failed: " + e.getMessage());
            return 2;
        }
    }

    private ScanConfig buildConfig() throws IOException {
        ScanConfig config;

        // Start from a file-based config if provided, otherwise use defaults
        if (configFile != null) {
            config = new ConfigLoader().loadFromFile(configFile);
        } else {
            config = new ScanConfig();
        }

        // CLI options override file-based config
        if (targetUrl != null) config.setTargetUrl(targetUrl);
        if (outputFile != null) config.setOutputFile(outputFile);
        if (threads != null) config.setThreads(threads);
        if (timeoutMinutes != null) config.setTimeoutMinutes(timeoutMinutes);
        if (verbose) config.setVerbose(true);
        if (noDiscovery) config.setDiscoveryEnabled(false);

        // Output format
        if (format != null) {
            try {
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(format.toUpperCase()));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid output format: " + format +
                        ". Supported: JSON, XML, HTML, SARIF");
            }
        }

        // Authentication
        if (bearerToken != null) config.setBearerToken(bearerToken);
        if (apiKey != null) config.setApiKey(apiKey);
        if (apiKeyHeader != null) config.setApiKeyHeader(apiKeyHeader);
        if (username != null) config.setBasicAuthUsername(username);
        if (password != null) config.setBasicAuthPassword(password);

        // Custom headers
        if (headers != null) {
            for (String header : headers) {
                int colon = header.indexOf(':');
                if (colon > 0) {
                    config.addHeader(header.substring(0, colon).trim(),
                            header.substring(colon + 1).trim());
                } else {
                    System.err.println("Warning: skipping invalid header (expected Key:Value): " + header);
                }
            }
        }

        // Proxy
        if (proxyUrl != null) {
            parseProxyUrl(proxyUrl, config);
        }

        // Test case selection
        if (enabledTestCases != null) {
            config.setEnabledTestCaseIds(List.of(enabledTestCases.split(",\\s*")));
        }
        if (disabledTestCases != null) {
            config.setDisabledTestCaseIds(List.of(disabledTestCases.split(",\\s*")));
        }

        // Add API key header if API key is configured but no header set yet
        if (config.getApiKey() != null && !config.getApiKey().isEmpty()) {
            String header = config.getApiKeyHeader() != null ? config.getApiKeyHeader() : "X-API-Key";
            config.addHeader(header, config.getApiKey());
        }

        return config;
    }

    private void validateConfig(ScanConfig config) {
        if (config.getTargetUrl() == null || config.getTargetUrl().isBlank()) {
            throw new IllegalArgumentException(
                    "Target URL is required. Provide --url or set targetUrl in config file.");
        }
        if (!config.getTargetUrl().startsWith("http://") && !config.getTargetUrl().startsWith("https://")) {
            throw new IllegalArgumentException(
                    "Target URL must start with http:// or https://");
        }
    }

    private void parseProxyUrl(String proxyUrl, ScanConfig config) {
        try {
            // Support formats: http://host:port or http://user:pass@host:port
            String url = proxyUrl.replaceFirst("^https?://", "");
            if (url.contains("@")) {
                String[] credAndHost = url.split("@", 2);
                String[] creds = credAndHost[0].split(":", 2);
                config.setProxyUsername(creds[0]);
                if (creds.length > 1) config.setProxyPassword(creds[1]);
                url = credAndHost[1];
            }
            String[] hostPort = url.split(":", 2);
            config.setProxyHost(hostPort[0]);
            if (hostPort.length > 1) config.setProxyPort(Integer.parseInt(hostPort[1]));
        } catch (Exception e) {
            System.err.println("Warning: could not parse proxy URL: " + proxyUrl);
        }
    }

    private void printResults(ScanResult result) {
        System.out.println("=".repeat(60));
        System.out.println("SCAN COMPLETE");
        System.out.println("=".repeat(60));
        System.out.printf("Target:          %s%n", result.getTargetUrl());
        System.out.printf("Total Findings:  %d%n", result.getTotalFindingsCount());

        Map<Severity, Long> summary = result.getSeveritySummary();
        System.out.println();
        System.out.println("Severity Breakdown:");
        System.out.printf("  CRITICAL: %d%n", summary.getOrDefault(Severity.CRITICAL, 0L));
        System.out.printf("  HIGH:     %d%n", summary.getOrDefault(Severity.HIGH, 0L));
        System.out.printf("  MEDIUM:   %d%n", summary.getOrDefault(Severity.MEDIUM, 0L));
        System.out.printf("  LOW:      %d%n", summary.getOrDefault(Severity.LOW, 0L));
        System.out.printf("  INFO:     %d%n", summary.getOrDefault(Severity.INFO, 0L));

        if (verbose && !result.getFindings().isEmpty()) {
            System.out.println();
            System.out.println("Findings:");
            System.out.println("-".repeat(60));
            for (Finding f : result.getFindings()) {
                System.out.printf("[%s] %s%n", f.getSeverity(), f.getTitle());
                System.out.printf("  Endpoint:    %s%n", f.getEndpoint());
                System.out.printf("  Test Case:   %s%n", f.getTestCaseId());
                System.out.printf("  Description: %s%n", f.getDescription().trim());
                if (f.getEvidence() != null) {
                    System.out.printf("  Evidence:    %s%n", f.getEvidence());
                }
                System.out.printf("  Remediation: %s%n", f.getRemediation().trim());
                System.out.println();
            }
        }
        System.out.println("=".repeat(60));
    }

    private void writeReport(ScanResult result, ScanConfig config) throws IOException {
        ReportGenerator generator = ReportGeneratorFactory.create(config);
        String reportContent = generator.generate(result);

        if (config.getOutputFile() != null && !config.getOutputFile().isBlank()) {
            generator.generateToFile(result, config.getOutputFile());
            System.out.println("Report written to: " + config.getOutputFile());
        } else {
            // Print to stdout if no output file specified
            System.out.println(reportContent);
        }
    }

    private void printBanner() {
        System.out.println();
        System.out.println("  ___  _       _ _____ _____");
        System.out.println(" / _ \\| |     | /  ___|_   _|   ______");
        System.out.println("/ /_\\ \\ |___  | \\ `--.  | |    |  ____|");
        System.out.println("|  _  | / __|  | |`--. \\ | |    | |__  ");
        System.out.println("| | | |  __/\\__/ /\\__/ / | |    |  __| ");
        System.out.println("\\_| |_/_\\___|\\___/\\____/  \\_/    |__|   ");
        System.out.println();
        System.out.println("  OWASP API Security Testing Framework v1.0.0");
        System.out.println("  https://owasp.org/www-project-api-security-testing-framework");
        System.out.println();
    }
}
