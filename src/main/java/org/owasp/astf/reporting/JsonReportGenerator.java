package org.owasp.astf.reporting;

import java.io.File;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Generates JSON reports from scan results.
 * <p>
 * This report generator creates JSON files containing all scan details and findings.
 * The JSON format is useful for automated processing, integration with other tools,
 * and creating custom visualizations.
 * </p>
 */
public class JsonReportGenerator implements ReportGenerator {
    private static final Logger logger = LogManager.getLogger(JsonReportGenerator.class);

    private final ObjectMapper objectMapper;

    /**
     * Creates a new JSON report generator with default settings.
     */
    public JsonReportGenerator() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public void generateReport(ScanResult result, String outputPath) throws IOException {
        logger.info("Generating JSON report at {}", outputPath);

        ObjectNode rootNode = objectMapper.createObjectNode();

        // Add report metadata
        rootNode.put("targetUrl", result.getTargetUrl());
        rootNode.put("scanStartTime", result.getScanStartTime().format(DateTimeFormatter.ISO_DATE_TIME));
        rootNode.put("scanEndTime", result.getScanEndTime().format(DateTimeFormatter.ISO_DATE_TIME));

        // Add summary information
        ObjectNode summaryNode = rootNode.putObject("summary");
        summaryNode.put("totalFindings", result.getTotalFindingsCount());

        // Add severity breakdown
        ObjectNode severityNode = summaryNode.putObject("bySeverity");
        Map<Severity, Long> severitySummary = result.getSeveritySummary();
        severityNode.put("critical", severitySummary.getOrDefault(Severity.CRITICAL, 0L));
        severityNode.put("high", severitySummary.getOrDefault(Severity.HIGH, 0L));
        severityNode.put("medium", severitySummary.getOrDefault(Severity.MEDIUM, 0L));
        severityNode.put("low", severitySummary.getOrDefault(Severity.LOW, 0L));
        severityNode.put("info", severitySummary.getOrDefault(Severity.INFO, 0L));

        // Add all findings
        ArrayNode findingsNode = rootNode.putArray("findings");
        for (Finding finding : result.getFindings()) {
            ObjectNode findingNode = findingsNode.addObject();
            findingNode.put("id", finding.getId());
            findingNode.put("title", finding.getTitle());
            findingNode.put("description", finding.getDescription());
            findingNode.put("severity", finding.getSeverity().name());
            findingNode.put("testCaseId", finding.getTestCaseId());
            findingNode.put("endpoint", finding.getEndpoint());

            // Add optional fields if present
            if (finding.getRequestDetails() != null) {
                findingNode.put("requestDetails", finding.getRequestDetails());
            }

            if (finding.getResponseDetails() != null) {
                findingNode.put("responseDetails", finding.getResponseDetails());
            }

            findingNode.put("remediation", finding.getRemediation());

            if (finding.getEvidence() != null) {
                findingNode.put("evidence", finding.getEvidence());
            }
        }

        // Write to the output file
        objectMapper.writeValue(new File(outputPath), rootNode);
        logger.info("JSON report generated successfully with {} findings", result.getTotalFindingsCount());
    }

    @Override
    public String getName() {
        return "JSON Report Generator";
    }

    @Override
    public String getFileExtension() {
        return "json";
    }
}