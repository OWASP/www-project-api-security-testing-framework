package org.owasp.astf.reporting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Generates security scan reports in SARIF (Static Analysis Results Interchange Format) 2.1.0.
 * SARIF is used by GitHub Advanced Security, Azure DevOps, and other CI/CD integrations.
 *
 * @see <a href="https://sarifweb.azurewebsites.net/">SARIF specification</a>
 */
public class SarifReportGenerator implements ReportGenerator {
    private static final Logger logger = LogManager.getLogger(SarifReportGenerator.class);
    private static final String SARIF_VERSION = "2.1.0";
    private static final String SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

    private final ObjectMapper mapper;

    public SarifReportGenerator() {
        this.mapper = new ObjectMapper();
    }

    @Override
    public String generate(ScanResult result) throws IOException {
        ObjectNode root = mapper.createObjectNode();
        root.put("$schema", SARIF_SCHEMA);
        root.put("version", SARIF_VERSION);

        ArrayNode runs = mapper.createArrayNode();
        ObjectNode run = mapper.createObjectNode();

        // Tool definition
        ObjectNode tool = mapper.createObjectNode();
        ObjectNode driver = mapper.createObjectNode();
        driver.put("name", "OWASP-ASTF");
        driver.put("fullName", "OWASP API Security Testing Framework");
        driver.put("version", "1.0.0");
        driver.put("informationUri", "https://github.com/OWASP/www-project-api-security-testing-framework");

        // Collect unique rules from findings
        Map<String, Finding> ruleMap = new LinkedHashMap<>();
        for (Finding f : result.getFindings()) {
            ruleMap.putIfAbsent(f.getTestCaseId() + ":" + sanitizeRuleId(f.getTitle()), f);
        }

        ArrayNode rules = mapper.createArrayNode();
        for (Map.Entry<String, Finding> entry : ruleMap.entrySet()) {
            Finding f = entry.getValue();
            ObjectNode rule = mapper.createObjectNode();
            rule.put("id", entry.getKey());
            rule.put("name", f.getTitle().replaceAll("[^a-zA-Z0-9]", ""));

            ObjectNode shortDesc = mapper.createObjectNode();
            shortDesc.put("text", f.getTitle());
            rule.set("shortDescription", shortDesc);

            ObjectNode fullDesc = mapper.createObjectNode();
            fullDesc.put("text", f.getDescription());
            rule.set("fullDescription", fullDesc);

            ObjectNode defaultConfig = mapper.createObjectNode();
            defaultConfig.put("level", toSarifLevel(f.getSeverity()));
            rule.set("defaultConfiguration", defaultConfig);

            ObjectNode help = mapper.createObjectNode();
            help.put("text", f.getRemediation());
            rule.set("help", help);

            ObjectNode properties = mapper.createObjectNode();
            properties.put("tags", "owasp-api-top10");
            properties.put("security-severity", toSecuritySeverityScore(f.getSeverity()));
            rule.set("properties", properties);

            rules.add(rule);
        }
        driver.set("rules", rules);
        tool.set("driver", driver);
        run.set("tool", tool);

        // Results
        ArrayNode resultsArray = mapper.createArrayNode();
        for (Finding f : result.getFindings()) {
            String ruleId = f.getTestCaseId() + ":" + sanitizeRuleId(f.getTitle());
            ObjectNode resultNode = mapper.createObjectNode();
            resultNode.put("ruleId", ruleId);
            resultNode.put("level", toSarifLevel(f.getSeverity()));

            ObjectNode message = mapper.createObjectNode();
            message.put("text", f.getDescription());
            resultNode.set("message", message);

            // Location
            ArrayNode locations = mapper.createArrayNode();
            ObjectNode location = mapper.createObjectNode();
            ObjectNode physicalLocation = mapper.createObjectNode();
            ObjectNode artifactLocation = mapper.createObjectNode();
            artifactLocation.put("uri", result.getTargetUrl() != null ? result.getTargetUrl() : "");
            physicalLocation.set("artifactLocation", artifactLocation);
            location.set("physicalLocation", physicalLocation);

            ObjectNode logicalLocation = mapper.createObjectNode();
            logicalLocation.put("name", f.getEndpoint());
            logicalLocation.put("kind", "member");
            location.set("logicalLocation", logicalLocation);
            locations.add(location);
            resultNode.set("locations", locations);

            // Properties
            ObjectNode properties = mapper.createObjectNode();
            properties.put("severity", f.getSeverity().name());
            if (f.getEvidence() != null) properties.put("evidence", f.getEvidence());
            if (f.getRemediation() != null) properties.put("remediation", f.getRemediation());
            resultNode.set("properties", properties);

            resultsArray.add(resultNode);
        }
        run.set("results", resultsArray);

        // Invocation
        ArrayNode invocations = mapper.createArrayNode();
        ObjectNode invocation = mapper.createObjectNode();
        invocation.put("executionSuccessful", true);
        if (result.getScanStartTime() != null) {
            invocation.put("startTimeUtc", result.getScanStartTime().toString());
        }
        if (result.getScanEndTime() != null) {
            invocation.put("endTimeUtc", result.getScanEndTime().toString());
        }
        invocations.add(invocation);
        run.set("invocations", invocations);

        runs.add(run);
        root.set("runs", runs);

        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    @Override
    public void generateToFile(ScanResult result, String outputPath) throws IOException {
        String content = generate(result);
        Files.write(Paths.get(outputPath), content.getBytes(StandardCharsets.UTF_8));
        logger.info("SARIF report written to {}", outputPath);
    }

    private String toSarifLevel(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM         -> "warning";
            case LOW, INFO      -> "note";
        };
    }

    private String toSecuritySeverityScore(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "9.8";
            case HIGH     -> "7.5";
            case MEDIUM   -> "5.3";
            case LOW      -> "3.1";
            case INFO     -> "1.0";
        };
    }

    private String sanitizeRuleId(String title) {
        return title.replaceAll("[^a-zA-Z0-9-]", "-").replaceAll("-+", "-").toLowerCase();
    }
}
