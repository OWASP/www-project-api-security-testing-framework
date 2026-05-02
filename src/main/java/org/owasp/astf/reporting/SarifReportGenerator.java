package org.owasp.astf.reporting;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Generates SARIF (Static Analysis Results Interchange Format) reports.
 * <p>
 * This report generator creates reports in the SARIF format, which is a standard
 * for static analysis tool results. This format is supported by many development tools
 * and platforms, including GitHub Code Scanning and Azure DevOps.
 * </p>
 * <p>
 * The SARIF format allows for detailed information about findings, including:
 * <ul>
 *   <li>Rule definitions with metadata</li>
 *   <li>Result locations with file paths</li>
 *   <li>Severity levels with standardized mapping</li>
 *   <li>Fix suggestions with code snippets</li>
 *   <li>Detailed contextual information</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html">SARIF Specification</a>
 */
public class SarifReportGenerator implements ReportGenerator {
    private static final Logger logger = LogManager.getLogger(SarifReportGenerator.class);

    private final ObjectMapper objectMapper;

    /**
     * Creates a new SARIF report generator.
     */
    public SarifReportGenerator() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void generateReport(ScanResult result, String outputPath) throws IOException {
        logger.info("Generating SARIF report at {}", outputPath);

        // Create SARIF report structure
        ObjectNode sarifNode = objectMapper.createObjectNode();
        sarifNode.put("$schema", "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        sarifNode.put("version", "2.1.0");

        ArrayNode runsArray = sarifNode.putArray("runs");
        ObjectNode runNode = runsArray.addObject();

        // Tool information
        ObjectNode toolNode = runNode.putObject("tool");
        ObjectNode toolDriverNode = toolNode.putObject("driver");
        toolDriverNode.put("name", "OWASP API Security Testing Framework");
        toolDriverNode.put("informationUri", "https://github.com/OWASP/api-security-testing-framework");
        toolDriverNode.put("semanticVersion", "1.0.0");
        toolDriverNode.put("version", "1.0.0");

        // Rules
        ArrayNode rulesArray = toolDriverNode.putArray("rules");

        // Create a map of test case IDs to rule nodes
        Map<String, ObjectNode> ruleMap = new HashMap<>();

        // Results
        ArrayNode resultsArray = runNode.putArray("results");

        // Generate rules and results
        for (Finding finding : result.getFindings()) {
            String testCaseId = finding.getTestCaseId();

            // Create rule if not exists
            if (!ruleMap.containsKey(testCaseId)) {
                ObjectNode ruleNode = rulesArray.addObject();
                ruleNode.put("id", testCaseId);

                // Short description
                ObjectNode shortDescNode = objectMapper.createObjectNode();
                shortDescNode.put("text", finding.getTitle());
                ruleNode.set("shortDescription", shortDescNode);

                // Full description
                ObjectNode fullDescNode = objectMapper.createObjectNode();
                fullDescNode.put("text", finding.getDescription());
                ruleNode.set("fullDescription", fullDescNode);

                // Help text (remediation)
                ObjectNode helpNode = ruleNode.putObject("help");
                helpNode.put("text", finding.getRemediation());

                // Properties
                ObjectNode propertiesNode = ruleNode.putObject("properties");
                propertiesNode.put("security-severity", getSarifSeverityNumber(finding.getSeverity()));

                // Tags
                ArrayNode tagsNode = objectMapper.createArrayNode();
                tagsNode.add("security");
                tagsNode.add("api");

                // Map OWASP categories
                if (testCaseId.contains("API1")) {
                    tagsNode.add("broken-object-level-authorization");
                    propertiesNode.put("category", "broken-object-level-authorization");
                } else if (testCaseId.contains("API2")) {
                    tagsNode.add("broken-authentication");
                    propertiesNode.put("category", "broken-authentication");
                } else if (testCaseId.contains("API3")) {
                    tagsNode.add("excessive-data-exposure");
                    propertiesNode.put("category", "excessive-data-exposure");
                } else if (testCaseId.contains("API4")) {
                    tagsNode.add("lack-of-resources-and-rate-limiting");
                    propertiesNode.put("category", "lack-of-resources-and-rate-limiting");
                } else if (testCaseId.contains("API5")) {
                    tagsNode.add("broken-function-level-authorization");
                    propertiesNode.put("category", "broken-function-level-authorization");
                }

                propertiesNode.set("tags", tagsNode);

                ruleMap.put(testCaseId, ruleNode);
            }

            // Create result
            ObjectNode resultNode = resultsArray.addObject();

            // Rule ID reference
            resultNode.put("ruleId", finding.getTestCaseId());

            // Set level based on severity
            String level = switch (finding.getSeverity()) {
                case CRITICAL, HIGH -> "error";
                case MEDIUM -> "warning";
                case LOW, INFO -> "note";
            };
            resultNode.put("level", level);

            // Message
            ObjectNode messageNode = resultNode.putObject("message");
            messageNode.put("text", finding.getTitle() + ": " + finding.getDescription());

            // Locations
            ArrayNode locationsArray = resultNode.putArray("locations");
            ObjectNode locationNode = locationsArray.addObject();

            ObjectNode physicalLocationNode = locationNode.putObject("physicalLocation");
            ObjectNode artifactLocationNode = physicalLocationNode.putObject("artifactLocation");

            // Extract endpoint path for URI
            String endpointPath = finding.getEndpoint();
            if (endpointPath != null && endpointPath.contains(" ")) {
                endpointPath = endpointPath.split("\\s+")[1];
            }

            artifactLocationNode.put("uri", result.getTargetUrl() + (endpointPath != null ? endpointPath : ""));
            artifactLocationNode.put("uriBaseId", "%SRCROOT%");

            // Add evidence if available
            if (finding.getEvidence() != null && !finding.getEvidence().isEmpty()) {
                ObjectNode regionNode = physicalLocationNode.putObject("region");
                regionNode.put("startLine", 1);
                regionNode.put("startColumn", 1);

                // Snippet
                ObjectNode snippetNode = objectMapper.createObjectNode();
                snippetNode.put("text", finding.getEvidence());
                regionNode.set("snippet", snippetNode);
            }

            // Add request/response as attachments if available
            if (finding.getRequestDetails() != null || finding.getResponseDetails() != null) {
                ArrayNode attachmentsArray = resultNode.putArray("attachments");

                if (finding.getRequestDetails() != null) {
                    ObjectNode attachmentNode = attachmentsArray.addObject();
                    attachmentNode.put("description", "HTTP Request");

                    ObjectNode contentNode = objectMapper.createObjectNode();
                    contentNode.put("text", finding.getRequestDetails());
                    attachmentNode.set("content", contentNode);
                }

                if (finding.getResponseDetails() != null) {
                    ObjectNode attachmentNode = attachmentsArray.addObject();
                    attachmentNode.put("description", "HTTP Response");

                    ObjectNode contentNode = objectMapper.createObjectNode();
                    contentNode.put("text", finding.getResponseDetails());
                    attachmentNode.set("content", contentNode);
                }
            }
        }

        // Write to file
        objectMapper.writerWithDefaultPrettyPrinter().writeValue(new File(outputPath), sarifNode);

        logger.info("SARIF report generated successfully with {} findings", result.getTotalFindingsCount());
    }

    /**
     * Converts an ASTF severity level to a SARIF security-severity number.
     * <p>
     * SARIF uses numbers between 0.0 and 10.0 for security severity,
     * similar to CVSS scores.
     * </p>
     *
     * @param severity The ASTF severity level
     * @return The SARIF security-severity number
     */
    private double getSarifSeverityNumber(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 9.8;   // Critical: Similar to CVSS 9.8
            case HIGH -> 8.0;       // High: Similar to CVSS 8.0
            case MEDIUM -> 5.0;     // Medium: Similar to CVSS 5.0
            case LOW -> 3.0;        // Low: Similar to CVSS 3.0
            case INFO -> 0.0;       // Info: Informational only
        };
    }

    @Override
    public String getName() {
        return "SARIF Report Generator";
    }

    @Override
    public String getFileExtension() {
        return "sarif";
    }
}