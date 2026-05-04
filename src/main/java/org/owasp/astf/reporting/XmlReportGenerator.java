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

/**
 * Generates security scan reports in XML format.
 */
public class XmlReportGenerator implements ReportGenerator {
    private static final Logger logger = LogManager.getLogger(XmlReportGenerator.class);
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    @Override
    public String generate(ScanResult result) throws IOException {
        Map<Severity, Long> summary = result.getSeveritySummary();
        StringBuilder sb = new StringBuilder();

        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        sb.append("<astf-report>\n");
        sb.append("  <tool>OWASP API Security Testing Framework</tool>\n");
        sb.append("  <version>1.0.0</version>\n");
        sb.append("  <targetUrl>").append(esc(result.getTargetUrl())).append("</targetUrl>\n");
        sb.append("  <scanStartTime>").append(
                result.getScanStartTime() != null ? result.getScanStartTime().format(FORMATTER) : "")
                .append("</scanStartTime>\n");
        sb.append("  <scanEndTime>").append(
                result.getScanEndTime() != null ? result.getScanEndTime().format(FORMATTER) : "")
                .append("</scanEndTime>\n");
        sb.append("  <totalFindings>").append(result.getTotalFindingsCount()).append("</totalFindings>\n");

        sb.append("  <severitySummary>\n");
        for (Severity sev : Severity.values()) {
            sb.append("    <").append(sev.name().toLowerCase()).append(">")
              .append(summary.getOrDefault(sev, 0L))
              .append("</").append(sev.name().toLowerCase()).append(">\n");
        }
        sb.append("  </severitySummary>\n");

        sb.append("  <findings>\n");
        for (Finding f : result.getFindings()) {
            sb.append("    <finding>\n");
            sb.append("      <id>").append(esc(f.getId())).append("</id>\n");
            sb.append("      <title>").append(esc(f.getTitle())).append("</title>\n");
            sb.append("      <description>").append(esc(f.getDescription())).append("</description>\n");
            sb.append("      <severity>").append(f.getSeverity().name()).append("</severity>\n");
            sb.append("      <testCaseId>").append(esc(f.getTestCaseId())).append("</testCaseId>\n");
            sb.append("      <endpoint>").append(esc(f.getEndpoint())).append("</endpoint>\n");
            sb.append("      <remediation>").append(esc(f.getRemediation())).append("</remediation>\n");
            if (f.getEvidence() != null) {
                sb.append("      <evidence>").append(esc(f.getEvidence())).append("</evidence>\n");
            }
            if (f.getRequestDetails() != null) {
                sb.append("      <requestDetails>").append(esc(f.getRequestDetails())).append("</requestDetails>\n");
            }
            if (f.getResponseDetails() != null) {
                sb.append("      <responseDetails>").append(esc(f.getResponseDetails())).append("</responseDetails>\n");
            }
            sb.append("    </finding>\n");
        }
        sb.append("  </findings>\n");
        sb.append("</astf-report>\n");

        return sb.toString();
    }

    @Override
    public void generateToFile(ScanResult result, String outputPath) throws IOException {
        String content = generate(result);
        Files.write(Paths.get(outputPath), content.getBytes(StandardCharsets.UTF_8));
        logger.info("XML report written to {}", outputPath);
    }

    private String esc(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }
}
