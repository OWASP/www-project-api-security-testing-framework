package org.owasp.astf.reporting;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("HTML Report Generator Tests")
class HtmlReportGeneratorTest {

    private HtmlReportGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new HtmlReportGenerator();
    }

    @Test
    @DisplayName("Should generate well-formed HTML")
    void testGenerateHtml() throws IOException {
        ScanResult result = new ScanResult("https://api.example.com", List.of());
        String html = generator.generate(result);

        assertNotNull(html);
        assertTrue(html.startsWith("<!DOCTYPE html>"), "Should start with DOCTYPE");
        assertTrue(html.contains("<html"), "Should contain html element");
        assertTrue(html.contains("</html>"), "Should close html element");
        assertTrue(html.contains("<body>"), "Should contain body");
        assertTrue(html.contains("</body>"), "Should close body");
    }

    @Test
    @DisplayName("Should include all findings in HTML output")
    void testFindingsInHtml() throws IOException {
        Finding f = new Finding(UUID.randomUUID().toString(), "SQL Injection",
                "SQL injection found in parameter.", Severity.CRITICAL,
                "ASTF-API1-2023", "GET /api/users", "Use parameterized queries.");
        f.setEvidence("' OR 1=1 returned 200");

        ScanResult result = new ScanResult("https://api.example.com", List.of(f));
        String html = generator.generate(result);

        assertTrue(html.contains("SQL Injection"), "Should contain finding title");
        assertTrue(html.contains("CRITICAL"), "Should contain severity");
        assertTrue(html.contains("parameterized queries"), "Should contain remediation");
    }

    @Test
    @DisplayName("Should show no-findings message for empty results")
    void testEmptyResultsMessage() throws IOException {
        ScanResult result = new ScanResult("https://api.example.com", List.of());
        String html = generator.generate(result);

        assertTrue(html.contains("no-findings") || html.contains("No security issues"),
                "Should show no-findings message");
    }

    @Test
    @DisplayName("Should escape HTML entities in finding content")
    void testHtmlEscaping() throws IOException {
        Finding f = new Finding(UUID.randomUUID().toString(),
                "XSS <script>alert('xss')</script>",
                "Description with <>&\"' chars.",
                Severity.HIGH, "ASTF-API8-2023",
                "GET /api/data", "Fix it.");

        ScanResult result = new ScanResult("https://api.example.com", List.of(f));
        String html = generator.generate(result);

        assertFalse(html.contains("<script>alert"),
                "Script tags should be escaped, not rendered");
        assertTrue(html.contains("&lt;script&gt;") || html.contains("alert"),
                "Should escape angle brackets");
    }

    @Test
    @DisplayName("Should include severity summary section")
    void testSeveritySummary() throws IOException {
        List<Finding> findings = List.of(
                new Finding(UUID.randomUUID().toString(), "Critical", "Desc", Severity.CRITICAL,
                        "ASTF-API1-2023", "GET /", "Fix"),
                new Finding(UUID.randomUUID().toString(), "High", "Desc", Severity.HIGH,
                        "ASTF-API1-2023", "GET /", "Fix")
        );

        ScanResult result = new ScanResult("https://api.example.com", findings);
        String html = generator.generate(result);

        assertTrue(html.contains("severity-critical") || html.contains("CRITICAL"),
                "Should show CRITICAL severity");
        assertTrue(html.contains("severity-high") || html.contains("HIGH"),
                "Should show HIGH severity");
    }
}
