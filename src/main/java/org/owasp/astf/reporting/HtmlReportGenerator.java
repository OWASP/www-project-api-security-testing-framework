package org.owasp.astf.reporting;

import java.io.FileWriter;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

/**
 * Generates HTML reports from scan results.
 * <p>
 * This report generator creates human-readable HTML files with interactive
 * features for exploring scan findings. The HTML report includes:
 * <ul>
 *   <li>Executive summary with vulnerability statistics</li>
 *   <li>Interactive finding details</li>
 *   <li>Evidence and remediation guidance</li>
 *   <li>Responsive design for various devices</li>
 * </ul>
 * </p>
 */
public class HtmlReportGenerator implements ReportGenerator {
    private static final Logger logger = LogManager.getLogger(HtmlReportGenerator.class);

    /**
     * Creates a new HTML report generator with default settings.
     */
    public HtmlReportGenerator() {
        // Default constructor
    }

    @Override
    public void generateReport(ScanResult result, String outputPath) throws IOException {
        logger.info("Generating HTML report at {}", outputPath);

        StringBuilder html = new StringBuilder();

        // Generate HTML header and styles
        generateHtmlHeader(html);

        // Generate summary section
        generateSummarySection(html, result);

        // Generate findings section
        generateFindingsSection(html, result);

        // Close HTML tags
        html.append("</body>\n</html>");

        // Write to the output file
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(html.toString());
        }

        logger.info("HTML report generated successfully with {} findings", result.getTotalFindingsCount());
    }

    /**
     * Generates the HTML header and CSS styles.
     *
     * @param html The StringBuilder to append to
     */
    private void generateHtmlHeader(StringBuilder html) {
        html.append("<!DOCTYPE html>\n")
                .append("<html lang=\"en\">\n")
                .append("<head>\n")
                .append("  <meta charset=\"UTF-8\">\n")
                .append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
                .append("  <title>OWASP API Security Scan Report</title>\n")
                .append("  <style>\n")
                .append("    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }\n")
                .append("    h1 { color: #2c3e50; }\n")
                .append("    h2 { color: #3498db; margin-top: 30px; }\n")
                .append("    .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }\n")
                .append("    .finding { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }\n")
                .append("    .critical { border-left: 5px solid #e74c3c; }\n")
                .append("    .high { border-left: 5px solid #e67e22; }\n")
                .append("    .medium { border-left: 5px solid #f1c40f; }\n")
                .append("    .low { border-left: 5px solid #3498db; }\n")
                .append("    .info { border-left: 5px solid #2ecc71; }\n")
                .append("    .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }\n")
                .append("    .severity.critical { background-color: #e74c3c; }\n")
                .append("    .severity.high { background-color: #e67e22; }\n")
                .append("    .severity.medium { background-color: #f1c40f; color: #333; }\n")
                .append("    .severity.low { background-color: #3498db; }\n")
                .append("    .severity.info { background-color: #2ecc71; }\n")
                .append("    .endpoint { background-color: #f8f9fa; padding: 5px; border-radius: 3px; font-family: monospace; }\n")
                .append("    .details { margin-top: 10px; }\n")
                .append("    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }\n")
                .append("    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
                .append("    th { background-color: #f2f2f2; }\n")
                .append("    .collapsible { cursor: pointer; }\n")
                .append("    .content { max-height: 0; overflow: hidden; transition: max-height 0.2s ease-out; }\n")
                .append("    .active + .content { max-height: 500px; }\n")
                .append("  </style>\n")
                .append("</head>\n")
                .append("<body>\n")
                .append("  <h1>OWASP API Security Testing Framework - Scan Report</h1>\n");
    }

    /**
     * Generates the summary section of the report.
     *
     * @param html The StringBuilder to append to
     * @param result The scan result
     */
    private void generateSummarySection(StringBuilder html, ScanResult result) {
        Map<Severity, Long> severitySummary = result.getSeveritySummary();

        html.append("  <div class=\"summary\">\n")
                .append("    <h2>Scan Summary</h2>\n")
                .append("    <p><strong>Target:</strong> ").append(result.getTargetUrl()).append("</p>\n")
                .append("    <p><strong>Scan Start:</strong> ").append(result.getScanStartTime().format(DateTimeFormatter.ISO_DATE_TIME)).append("</p>\n")
                .append("    <p><strong>Scan End:</strong> ").append(result.getScanEndTime().format(DateTimeFormatter.ISO_DATE_TIME)).append("</p>\n")
                .append("    <p><strong>Total Findings:</strong> ").append(result.getTotalFindingsCount()).append("</p>\n")
                .append("    <table>\n")
                .append("      <tr><th>Severity</th><th>Count</th></tr>\n");

        html.append("      <tr><td>Critical</td><td>").append(severitySummary.getOrDefault(Severity.CRITICAL, 0L)).append("</td></tr>\n")
                .append("      <tr><td>High</td><td>").append(severitySummary.getOrDefault(Severity.HIGH, 0L)).append("</td></tr>\n")
                .append("      <tr><td>Medium</td><td>").append(severitySummary.getOrDefault(Severity.MEDIUM, 0L)).append("</td></tr>\n")
                .append("      <tr><td>Low</td><td>").append(severitySummary.getOrDefault(Severity.LOW, 0L)).append("</td></tr>\n")
                .append("      <tr><td>Info</td><td>").append(severitySummary.getOrDefault(Severity.INFO, 0L)).append("</td></tr>\n")
                .append("    </table>\n")
                .append("  </div>\n");
    }

    /**
     * Generates the findings section of the report.
     *
     * @param html The StringBuilder to append to
     * @param result The scan result
     */
    private void generateFindingsSection(StringBuilder html, ScanResult result) {
        if (result.getTotalFindingsCount() == 0) {
            html.append("  <div class=\"findings\">\n")
                    .append("    <h2>Findings</h2>\n")
                    .append("    <p>No security findings were detected during the scan.</p>\n")
                    .append("  </div>\n");
            return;
        }

        html.append("  <div class=\"findings\">\n")
                .append("    <h2>Findings</h2>\n");

        // Group findings by severity for better organization
        Map<Severity, List<Finding>> findingsBySeverity = result.getFindings().stream()
                .collect(Collectors.groupingBy(Finding::getSeverity));

        // Process findings in order of severity
        processFindingsBySeverity(html, findingsBySeverity, Severity.CRITICAL);
        processFindingsBySeverity(html, findingsBySeverity, Severity.HIGH);
        processFindingsBySeverity(html, findingsBySeverity, Severity.MEDIUM);
        processFindingsBySeverity(html, findingsBySeverity, Severity.LOW);
        processFindingsBySeverity(html, findingsBySeverity, Severity.INFO);

        html.append("  </div>\n");

        // Add JavaScript for collapsible sections
        html.append("<script>\n")
                .append("  document.addEventListener('DOMContentLoaded', function() {\n")
                .append("    var collapsibles = document.getElementsByClassName('collapsible');\n")
                .append("    for (var i = 0; i < collapsibles.length; i++) {\n")
                .append("      collapsibles[i].addEventListener('click', function() {\n")
                .append("        this.classList.toggle('active');\n")
                .append("      });\n")
                .append("    }\n")
                .append("  });\n")
                .append("</script>\n");
    }

    /**
     * Processes findings for a specific severity level.
     *
     * @param html The StringBuilder to append to
     * @param findingsBySeverity Map of findings grouped by severity
     * @param severity The severity level to process
     */
    private void processFindingsBySeverity(StringBuilder html, Map<Severity, List<Finding>> findingsBySeverity, Severity severity) {
        List<Finding> findings = findingsBySeverity.get(severity);
        if (findings == null || findings.isEmpty()) {
            return;
        }

        String severityClass = severity.name().toLowerCase();

        html.append("    <h3>").append(severity).append(" Severity Findings (").append(findings.size()).append(")</h3>\n");

        for (Finding finding : findings) {
            html.append("    <div class=\"finding ").append(severityClass).append("\">\n")
                    .append("      <h4>")
                    .append(finding.getTitle())
                    .append(" <span class=\"severity ").append(severityClass).append("\">").append(severity).append("</span></h4>\n")
                    .append("      <p><strong>Endpoint:</strong> <span class=\"endpoint\">").append(finding.getEndpoint()).append("</span></p>\n")
                    .append("      <p><strong>Test Case:</strong> ").append(finding.getTestCaseId()).append("</p>\n")
                    .append("      <div class=\"details\">\n")
                    .append("        <p>").append(finding.getDescription()).append("</p>\n");

            // Add evidence if available
            if (finding.getEvidence() != null && !finding.getEvidence().isEmpty()) {
                html.append("        <p><strong>Evidence:</strong> ").append(finding.getEvidence()).append("</p>\n");
            }

            // Add request/response details if available
            if (finding.getRequestDetails() != null || finding.getResponseDetails() != null) {
                html.append("        <h5 class=\"collapsible\">Request/Response Details</h5>\n")
                        .append("        <div class=\"content\">\n");

                if (finding.getRequestDetails() != null) {
                    html.append("          <p><strong>Request:</strong><br><pre>").append(escapeHtml(finding.getRequestDetails())).append("</pre></p>\n");
                }

                if (finding.getResponseDetails() != null) {
                    html.append("          <p><strong>Response:</strong><br><pre>").append(escapeHtml(finding.getResponseDetails())).append("</pre></p>\n");
                }

                html.append("        </div>\n");
            }

            // Add remediation guidance
            html.append("        <h5 class=\"collapsible\">Remediation</h5>\n")
                    .append("        <div class=\"content\">\n")
                    .append("          <p>").append(finding.getRemediation()).append("</p>\n")
                    .append("        </div>\n")
                    .append("      </div>\n")
                    .append("    </div>\n");
        }
    }

    /**
     * Escapes HTML special characters in a string.
     *
     * @param input The input string
     * @return The escaped string
     */
    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }

        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    @Override
    public String getName() {
        return "HTML Report Generator";
    }

    @Override
    public String getFileExtension() {
        return "html";
    }
}