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

@DisplayName("SARIF Report Generator Tests")
class SarifReportGeneratorTest {

    private SarifReportGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new SarifReportGenerator();
    }

    @Test
    @DisplayName("Should generate valid SARIF 2.1.0 structure")
    void testSarifStructure() throws IOException {
        ScanResult result = new ScanResult("https://api.example.com", List.of());
        String sarif = generator.generate(result);

        assertNotNull(sarif);
        assertTrue(sarif.contains("\"version\" : \"2.1.0\"") || sarif.contains("\"version\":\"2.1.0\""),
                "Should have SARIF version 2.1.0");
        assertTrue(sarif.contains("\"$schema\""), "Should have schema reference");
        assertTrue(sarif.contains("\"runs\""), "Should have runs array");
        assertTrue(sarif.contains("\"tool\""), "Should have tool section");
        assertTrue(sarif.contains("OWASP-ASTF"), "Should have tool name");
    }

    @Test
    @DisplayName("Should map CRITICAL severity to SARIF error level")
    void testSeverityMapping() throws IOException {
        Finding f = new Finding(UUID.randomUUID().toString(), "Critical Finding",
                "Description", Severity.CRITICAL, "ASTF-API1-2023",
                "GET /api/users", "Fix it.");

        ScanResult result = new ScanResult("https://api.example.com", List.of(f));
        String sarif = generator.generate(result);

        assertTrue(sarif.contains("\"error\""),
                "CRITICAL should map to SARIF 'error' level");
    }

    @Test
    @DisplayName("Should map MEDIUM severity to SARIF warning level")
    void testMediumSeverityMapping() throws IOException {
        Finding f = new Finding(UUID.randomUUID().toString(), "Medium Finding",
                "Description", Severity.MEDIUM, "ASTF-API4-2023",
                "GET /api/data", "Fix it.");

        ScanResult result = new ScanResult("https://api.example.com", List.of(f));
        String sarif = generator.generate(result);

        assertTrue(sarif.contains("\"warning\""),
                "MEDIUM should map to SARIF 'warning' level");
    }

    @Test
    @DisplayName("Should include rule definitions in driver")
    void testRuleDefinitions() throws IOException {
        Finding f = new Finding(UUID.randomUUID().toString(), "Test Finding",
                "Description", Severity.HIGH, "ASTF-API2-2023",
                "POST /api/login", "Fix it.");

        ScanResult result = new ScanResult("https://api.example.com", List.of(f));
        String sarif = generator.generate(result);

        assertTrue(sarif.contains("\"rules\""), "Should have rules section");
        assertTrue(sarif.contains("ASTF-API2-2023"), "Should reference test case ID");
    }

    @Test
    @DisplayName("Should produce valid SARIF for empty results")
    void testEmptyResults() throws IOException {
        ScanResult result = new ScanResult("https://api.example.com", List.of());
        String sarif = generator.generate(result);

        assertNotNull(sarif);
        assertTrue(sarif.contains("\"results\""), "Should have results section");
    }
}
