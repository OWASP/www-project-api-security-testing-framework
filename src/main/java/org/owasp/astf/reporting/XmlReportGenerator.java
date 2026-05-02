package org.owasp.astf.reporting;

import java.io.FileWriter;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

/**
 * Generates XML reports from scan results.
 * <p>
 * This report generator creates XML files with scan findings and metadata.
 * The XML format is useful for integration with other tools and systems
 * that can parse XML data.
 * </p>
 */
public class XmlReportGenerator implements ReportGenerator {
    private static final Logger logger = LogManager.getLogger(XmlReportGenerator.class);

    /**
     * Creates a new XML report generator.
     */
    public XmlReportGenerator() {
        // Default constructor
    }

    @Override
    public void generateReport(ScanResult result, String outputPath) throws IOException {
        logger.info("Generating XML report at {}", outputPath);

        StringBuilder xml = new StringBuilder();

        // XML header
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<scanReport>\n");

        // Scan metadata
        xml.append("  <targetUrl>").append(escapeXml(result.getTargetUrl())).append("</targetUrl>\n");
        xml.append("  <scanStartTime>").append(result.getScanStartTime().format(DateTimeFormatter.ISO_DATE_TIME)).append("</scanStartTime>\n");
        xml.append("  <scanEndTime>").append(result.getScanEndTime().format(DateTimeFormatter.ISO_DATE_TIME)).append("</scanEndTime>\n");

        // Summary
        xml.append("  <summary>\n");
        xml.append("    <totalFindings>").append(result.getTotalFindingsCount()).append("</totalFindings>\n");

        // Severity breakdown
        xml.append("    <bySeverity>\n");
        Map<Severity, Long> severitySummary = result.getSeveritySummary();
        xml.append("      <critical>").append(severitySummary.getOrDefault(Severity.CRITICAL, 0L)).append("</critical>\n");
        xml.append("      <high>").append(severitySummary.getOrDefault(Severity.HIGH, 0L)).append("</high>\n");
        xml.append("      <medium>").append(severitySummary.getOrDefault(Severity.MEDIUM, 0L)).append("</medium>\n");
        xml.append("      <low>").append(severitySummary.getOrDefault(Severity.LOW, 0L)).append("</low>\n");
        xml.append("      <info>").append(severitySummary.getOrDefault(Severity.INFO, 0L)).append("</info>\n");
        xml.append("    </bySeverity>\n");
        xml.append("  </summary>\n");

        // Findings
        xml.append("  <findings>\n");

        for (Finding finding : result.getFindings()) {
            xml.append("    <finding>\n");
            xml.append("      <id>").append(escapeXml(finding.getId())).append("</id>\n");
            xml.append("      <title>").append(escapeXml(finding.getTitle())).append("</title>\n");
            xml.append("      <description>").append(escapeXml(finding.getDescription())).append("</description>\n");
            xml.append("      <severity>").append(finding.getSeverity()).append("</severity>\n");
            xml.append("      <testCaseId>").append(escapeXml(finding.getTestCaseId())).append("</testCaseId>\n");
            xml.append("      <endpoint>").append(escapeXml(finding.getEndpoint())).append("</endpoint>\n");

            // Optional fields
            if (finding.getRequestDetails() != null) {
                xml.append("      <requestDetails>").append(escapeXml(finding.getRequestDetails())).append("</requestDetails>\n");
            }

            if (finding.getResponseDetails() != null) {
                xml.append("      <responseDetails>").append(escapeXml(finding.getResponseDetails())).append("</responseDetails>\n");
            }

            xml.append("      <remediation>").append(escapeXml(finding.getRemediation())).append("</remediation>\n");

            if (finding.getEvidence() != null) {
                xml.append("      <evidence>").append(escapeXml(finding.getEvidence())).append("</evidence>\n");
            }

            xml.append("    </finding>\n");
        }

        xml.append("  </findings>\n");
        xml.append("</scanReport>");

        // Write to file
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(xml.toString());
        }

        logger.info("XML report generated successfully with {} findings", result.getTotalFindingsCount());
    }

    /**
     * Escapes XML special characters in a string.
     *
     * @param input The input string
     * @return The escaped string
     */
    private String escapeXml(String input) {
        if (input == null) {
            return "";
        }

        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    @Override
    public String getName() {
        return "XML Report Generator";
    }

    @Override
    public String getFileExtension() {
        return "xml";
    }
}