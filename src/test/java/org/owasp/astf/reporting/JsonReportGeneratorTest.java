package org.owasp.astf.reporting;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JSON Report Generator Tests")
class JsonReportGeneratorTest {

    private JsonReportGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new JsonReportGenerator();
    }

    @Test
    @DisplayName("Should generate valid JSON report")
    void testGenerateJson() throws IOException {
        ScanResult result = createSampleResult();
        String json = generator.generate(result);

        assertNotNull(json);
        assertTrue(json.contains("\"targetUrl\""), "Should contain target URL field");
        assertTrue(json.contains("\"findings\""), "Should contain findings array");
        assertTrue(json.contains("\"severitySummary\""), "Should contain severity summary");
        assertTrue(json.contains("OWASP API Security Testing Framework"), "Should contain tool name");
    }

    @Test
    @DisplayName("Should include all finding fields in JSON output")
    void testFindingFields() throws IOException {
        Finding f = new Finding(UUID.randomUUID().toString(), "Test Finding",
                "Test description", Severity.HIGH, "ASTF-API1-2023",
                "GET /api/users/1", "Fix the issue");
        f.setEvidence("Evidence text");
        f.setRequestDetails("GET /api/users/1");
        f.setResponseDetails("HTTP 200");

        ScanResult result = new ScanResult("https://example.com", List.of(f));
        String json = generator.generate(result);

        assertTrue(json.contains("\"title\""), "Should contain title");
        assertTrue(json.contains("Test Finding"), "Should contain finding title value");
        assertTrue(json.contains("\"severity\""), "Should contain severity");
        assertTrue(json.contains("HIGH"), "Should contain severity value");
        assertTrue(json.contains("\"evidence\""), "Should contain evidence");
        assertTrue(json.contains("Evidence text"), "Should contain evidence value");
        assertTrue(json.contains("\"remediation\""), "Should contain remediation");
    }

    @Test
    @DisplayName("Should generate valid JSON for empty results")
    void testEmptyResults() throws IOException {
        ScanResult result = new ScanResult("https://example.com", List.of());
        String json = generator.generate(result);

        assertNotNull(json);
        // Jackson pretty-printer uses spaces around ':' so match flexibly
        assertTrue(json.replaceAll("\\s", "").contains("\"totalFindings\":0"),
                "Should have 0 total findings");
        assertTrue(json.replaceAll("\\s", "").contains("\"findings\":[]")
                        || json.contains("\"findings\" : [ ]"),
                "Should have empty findings array");
    }

    @Test
    @DisplayName("Should write report to file")
    void testGenerateToFile(@TempDir Path tempDir) throws IOException {
        ScanResult result = createSampleResult();
        Path outputFile = tempDir.resolve("report.json");

        generator.generateToFile(result, outputFile.toString());

        assertTrue(Files.exists(outputFile), "Output file should be created");
        String content = Files.readString(outputFile);
        assertTrue(content.contains("\"findings\""), "File should contain findings");
    }

    @Test
    @DisplayName("Should correctly count findings by severity")
    void testSeveritySummary() throws IOException {
        List<Finding> findings = List.of(
                makeFinding("Critical 1", Severity.CRITICAL),
                makeFinding("High 1", Severity.HIGH),
                makeFinding("High 2", Severity.HIGH),
                makeFinding("Medium 1", Severity.MEDIUM)
        );

        ScanResult result = new ScanResult("https://example.com", findings);
        result.setScanStartTime(LocalDateTime.now().minusMinutes(2));
        result.setScanEndTime(LocalDateTime.now());
        String json = generator.generate(result);

        // Strip whitespace before comparing so both compact and pretty-printed JSON match
        String compactJson = json.replaceAll("\\s", "");
        assertTrue(compactJson.contains("\"CRITICAL\":1"), "Should have 1 CRITICAL");
        assertTrue(compactJson.contains("\"HIGH\":2"),     "Should have 2 HIGH");
        assertTrue(compactJson.contains("\"MEDIUM\":1"),   "Should have 1 MEDIUM");
    }

    private ScanResult createSampleResult() {
        Finding f = makeFinding("SQL Injection Found", Severity.CRITICAL);
        ScanResult result = new ScanResult("https://api.example.com", List.of(f));
        result.setScanStartTime(LocalDateTime.now().minusMinutes(5));
        result.setScanEndTime(LocalDateTime.now());
        return result;
    }

    private Finding makeFinding(String title, Severity severity) {
        return new Finding(UUID.randomUUID().toString(), title, "Description of " + title,
                severity, "ASTF-API1-2023", "GET /api/test", "Apply proper fix.");
    }
}
