package org.owasp.astf.integrations.providers.github;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.core.ResultProcessor;
import org.owasp.astf.integrations.security.SecurityConfiguration;
import org.owasp.astf.reporting.ReportGenerator;
import org.owasp.astf.reporting.ReportGeneratorFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Processes and publishes scan results in GitHub Actions.
 * This class handles result formatting, reporting, and integration
 * with GitHub's annotation and check system.
 */
public class GitHubActionsResultProcessor implements ResultProcessor {
    private static final Logger logger = LogManager.getLogger(GitHubActionsResultProcessor.class);
    private static final DateTimeFormatter timeFormatter = DateTimeFormatter.ISO_DATE_TIME;

    @Override
    public boolean processResults(ScanResult results, CIEnvironment environment) {
        logger.info("Processing scan results for GitHub Actions");

        try {
            // Create output directory if it doesn't exist
            Path outputDir = Paths.get(environment.getWorkspaceDirectory(), "scan-results");
            if (!Files.exists(outputDir)) {
                Files.createDirectories(outputDir);
            }

            // Write summary as markdown
            writeSummaryMarkdown(results, outputDir);

            // Write detailed results as JSON
            createReport(results, ScanConfig.OutputFormat.JSON, outputDir.resolve("results.json").toFile());

            // Write SARIF format for GitHub Code Scanning
            createReport(results, ScanConfig.OutputFormat.SARIF, outputDir.resolve("results.sarif").toFile());

            // Write HTML report for detailed view
            createReport(results, ScanConfig.OutputFormat.HTML, outputDir.resolve("report.html").toFile());

            return true;
        } catch (Exception e) {
            logger.error("Failed to process scan results: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public boolean publishResults(ScanResult results, CIEnvironment environment) {
        logger.info("Publishing scan results in GitHub Actions");

        try {
            if (environment instanceof GitHubActionsEnvironment) {
                GitHubActionsEnvironment ghEnv = (GitHubActionsEnvironment) environment;

                // Create GitHub Actions step summary
                String stepSummaryFile = ghEnv.getEnvironmentVariable("GITHUB_STEP_SUMMARY").orElse(null);
                if (stepSummaryFile != null) {
                    logger.info("Writing step summary to {}", stepSummaryFile);
                    try (BufferedWriter writer = new BufferedWriter(new FileWriter(stepSummaryFile, true))) {
                        writer.write(generateSummary(results));
                    }
                }

                // Create GitHub Actions annotations
                createAnnotations(results, ghEnv);

                // If in a PR, comment on the PR with a summary
                if (ghEnv.isPullRequest()) {
                    // This would be implemented using the GitHub API, but requires additional dependencies
                    logger.info("Skipping PR comment (requires GitHub API integration)");
                }

                return true;
            }

            logger.warn("Not running in GitHub Actions, skipping publishing");
            return false;
        } catch (Exception e) {
            logger.error("Failed to publish scan results: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public boolean shouldFailBuild(ScanResult results, Map<Severity, Integer> thresholds) {
        // Get severity counts
        Map<Severity, Long> counts = results.getSeveritySummary();

        // Check against thresholds
        for (Map.Entry<Severity, Integer> threshold : thresholds.entrySet()) {
            Severity severity = threshold.getKey();
            int maxAllowed = threshold.getValue();

            long count = counts.getOrDefault(severity, 0L);
            if (count > maxAllowed) {
                logger.info("Build should fail: Found {} {} severity issues (threshold: {})",
                        count, severity, maxAllowed);
                return true;
            }
        }

        logger.info("Build should pass: All findings are within thresholds");
        return false;
    }

    @Override
    public String generateSummary(ScanResult results) {
        StringBuilder sb = new StringBuilder();

        // Add header
        sb.append("# API Security Scan Results\n\n");

        // Add scan metadata
        sb.append("## Scan Information\n\n");
        sb.append("- **Target URL**: ").append(results.getTargetUrl()).append("\n");
        sb.append("- **Scan Time**: ").append(results.getScanStartTime().format(timeFormatter)).append("\n");
        sb.append("- **Duration**: ").append(
                results.getScanEndTime().toLocalTime().toSecondOfDay() -
                        results.getScanStartTime().toLocalTime().toSecondOfDay()
        ).append(" seconds\n\n");

        // Add findings summary
        sb.append("## Findings Summary\n\n");
        Map<Severity, Long> severityCounts = results.getSeveritySummary();

        sb.append("| Severity | Count |\n");
        sb.append("|----------|-------|\n");
        for (Severity severity : Severity.values()) {
            sb.append("| **").append(severity).append("** | ")
                    .append(severityCounts.getOrDefault(severity, 0L)).append(" |\n");
        }
        sb.append("\n");

        // Add top findings
        sb.append("## Top Findings\n\n");
        List<Finding> topFindings = getHighlightedFindings(results, 10);

        if (topFindings.isEmpty()) {
            sb.append("No findings to display.\n\n");
        } else {
            for (Finding finding : topFindings) {
                sb.append("### ").append(finding.getTitle()).append("\n\n");
                sb.append("- **Severity**: ").append(finding.getSeverity()).append("\n");
                sb.append("- **Endpoint**: ").append(finding.getEndpoint()).append("\n");
                sb.append("- **Description**: ").append(finding.getDescription()).append("\n");
                sb.append("- **Remediation**: ").append(finding.getRemediation()).append("\n\n");
            }
        }

        return sb.toString();
    }

    @Override
    public boolean createReport(ScanResult results, ScanConfig.OutputFormat format, File outputFile) {
        try {
            // Use the existing ReportGeneratorFactory to create the appropriate generator
            ReportGenerator generator = ReportGeneratorFactory.createGenerator(format);

            // Generate the report
            generator.generateReport(results, outputFile.getAbsolutePath());

            logger.info("Created {} report at {}", format, outputFile.getAbsolutePath());
            return true;
        } catch (Exception e) {
            logger.error("Failed to create {} report: {}", format, e.getMessage());
            return false;
        }
    }

    @Override
    public List<Finding> getHighlightedFindings(ScanResult results, int limit) {
        // Sort findings by severity (highest first)
        return results.getFindings().stream()
                .sorted((f1, f2) -> {
                    // First by severity (high to low)
                    int severityCompare = f2.getSeverity().compareTo(f1.getSeverity());
                    if (severityCompare != 0) {
                        return severityCompare;
                    }
                    // Then by title (alphabetically)
                    return f1.getTitle().compareTo(f2.getTitle());
                })
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Override
    public String formatFinding(Finding finding) {
        StringBuilder sb = new StringBuilder();

        sb.append(finding.getSeverity()).append(": ")
                .append(finding.getTitle())
                .append(" (").append(finding.getEndpoint()).append(")");

        return sb.toString();
    }

    @Override
    public ScanResult sanitizeResults(ScanResult results) {
        // Use the SecurityConfiguration utility class for sanitization
        return SecurityConfiguration.sanitizeResults(results);
    }

    /**
     * Creates GitHub Actions annotations for findings.
     *
     * @param results The scan results
     * @param environment The GitHub Actions environment
     */
    private void createAnnotations(ScanResult results, GitHubActionsEnvironment environment) {
        // Get top findings to annotate (limit by severity to avoid too many annotations)
        List<Finding> findings = results.getFindings().stream()
                .filter(f -> f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH)
                .limit(20)
                .collect(Collectors.toList());

        // If we don't have any critical or high findings, include some medium ones
        if (findings.isEmpty()) {
            findings = results.getFindings().stream()
                    .filter(f -> f.getSeverity() == Severity.MEDIUM)
                    .limit(10)
                    .collect(Collectors.toList());
        }

        for (Finding finding : findings) {
            String level = finding.getSeverity() == Severity.CRITICAL || finding.getSeverity() == Severity.HIGH
                    ? "error" : "warning";

            // Format for GitHub Actions annotation
            // https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message
            System.out.println(String.format("::%s::%s", level, escapeAnnotation(formatFinding(finding))));
        }
    }

    /**
     * Escapes a string for use in GitHub Actions annotations.
     *
     * @param s The string to escape
     * @return The escaped string
     */
    private String escapeAnnotation(String s) {
        return s.replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A")
                .replace(":", "%3A")
                .replace(",", "%2C");
    }

    /**
     * Writes a summary of the scan results as a markdown file.
     *
     * @param results The scan results
     * @param outputDir The output directory
     * @throws IOException If an I/O error occurs
     */
    private void writeSummaryMarkdown(ScanResult results, Path outputDir) throws IOException {
        Path outputFile = outputDir.resolve("summary.md");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile.toFile()))) {
            writer.write(generateSummary(results));
        }

        logger.info("Wrote summary markdown to {}", outputFile);
    }
}