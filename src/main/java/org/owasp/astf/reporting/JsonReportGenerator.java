package org.owasp.astf.reporting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;
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
 * Generates security scan reports in JSON format.
 */
public class JsonReportGenerator implements ReportGenerator {
    private static final Logger logger = LogManager.getLogger(JsonReportGenerator.class);
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final ObjectMapper mapper;

    public JsonReportGenerator() {
        this.mapper = new ObjectMapper();
    }

    @Override
    public String generate(ScanResult result) throws IOException {
        ObjectNode root = mapper.createObjectNode();

        root.put("tool", "OWASP API Security Testing Framework");
        root.put("version", "1.0.0");
        root.put("targetUrl", result.getTargetUrl());
        root.put("scanStartTime", result.getScanStartTime() != null
                ? result.getScanStartTime().format(FORMATTER) : "");
        root.put("scanEndTime", result.getScanEndTime() != null
                ? result.getScanEndTime().format(FORMATTER) : "");
        root.put("totalFindings", result.getTotalFindingsCount());

        // Severity summary
        ObjectNode summary = mapper.createObjectNode();
        Map<Severity, Long> severitySummary = result.getSeveritySummary();
        for (Severity sev : Severity.values()) {
            summary.put(sev.name(), severitySummary.getOrDefault(sev, 0L));
        }
        root.set("severitySummary", summary);

        // Findings
        ArrayNode findingsArray = mapper.createArrayNode();
        for (Finding f : result.getFindings()) {
            ObjectNode node = mapper.createObjectNode();
            node.put("id", f.getId());
            node.put("title", f.getTitle());
            node.put("description", f.getDescription());
            node.put("severity", f.getSeverity().name());
            node.put("testCaseId", f.getTestCaseId());
            node.put("endpoint", f.getEndpoint());
            node.put("remediation", f.getRemediation());
            if (f.getEvidence() != null)        node.put("evidence", f.getEvidence());
            if (f.getRequestDetails() != null)  node.put("requestDetails", f.getRequestDetails());
            if (f.getResponseDetails() != null) node.put("responseDetails", f.getResponseDetails());
            findingsArray.add(node);
        }
        root.set("findings", findingsArray);

        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    @Override
    public void generateToFile(ScanResult result, String outputPath) throws IOException {
        String content = generate(result);
        Files.write(Paths.get(outputPath), content.getBytes(StandardCharsets.UTF_8));
        logger.info("JSON report written to {}", outputPath);
    }
}
