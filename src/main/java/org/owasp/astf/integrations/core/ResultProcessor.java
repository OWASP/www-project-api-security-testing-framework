package org.owasp.astf.integrations.core;

import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import java.io.File;
import java.util.List;
import java.util.Map;

/**
 * Processes scan results for CI/CD platforms.
 * This interface defines methods for processing, formatting, and publishing
 * security scan results in CI/CD environments.
 */
public interface ResultProcessor {

    /**
     * Processes scan results for the CI/CD platform.
     *
     * @param results The scan results to process
     * @param environment The CI environment
     * @return true if processing was successful, false otherwise
     */
    boolean processResults(ScanResult results, CIEnvironment environment);

    /**
     * Publishes scan results to the CI/CD platform.
     *
     * @param results The scan results to publish
     * @param environment The CI environment
     * @return true if publishing was successful, false otherwise
     */
    boolean publishResults(ScanResult results, CIEnvironment environment);

    /**
     * Determines if the build should fail based on the scan results and thresholds.
     *
     * @param results The scan results
     * @param thresholds The severity thresholds for different finding types, keyed by severity
     * @return true if the build should fail, false otherwise
     */
    boolean shouldFailBuild(ScanResult results, Map<Severity, Integer> thresholds);

    /**
     * Generates a summary of the scan results for display in the CI/CD platform.
     *
     * @param results The scan results
     * @return A text summary of the results
     */
    String generateSummary(ScanResult results);

    /**
     * Creates a report file in the appropriate format for the CI/CD platform.
     * This method uses the ReportGeneratorFactory to create the appropriate
     * report generator for the specified format.
     *
     * @param results The scan results
     * @param format The report format
     * @param outputFile The output file
     * @return true if the report was successfully created, false otherwise
     */
    boolean createReport(ScanResult results, ScanConfig.OutputFormat format, File outputFile);

    /**
     * Gets the findings that should be highlighted in the CI/CD platform.
     * This may be a subset of all findings, based on severity or other criteria.
     *
     * @param results The scan results
     * @param limit The maximum number of findings to return
     * @return The list of findings to highlight
     */
    List<Finding> getHighlightedFindings(ScanResult results, int limit);

    /**
     * Formats a finding for display in the CI/CD platform.
     *
     * @param finding The finding to format
     * @return A formatted string representation of the finding
     */
    String formatFinding(Finding finding);

    /**
     * Sanitizes sensitive information in scan results.
     * This is used when publishing results to public environments.
     *
     * @param results The scan results to sanitize
     * @return A sanitized copy of the results
     */
    ScanResult sanitizeResults(ScanResult results);
}