package org.owasp.astf.integration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GitHubActionsIntegration Tests")
class GitHubActionsIntegrationTest {

    private ByteArrayOutputStream outputCapture;
    private GitHubActionsIntegration integration;

    @BeforeEach
    void setUp() {
        outputCapture = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(outputCapture);
        // Simulate running inside GitHub Actions
        integration = new GitHubActionsIntegration(ps, Map.of("GITHUB_ACTIONS", "true"));
    }

    @Test
    @DisplayName("Should return correct integration name")
    void testGetName() {
        assertEquals("GitHub Actions", integration.getName());
    }

    @Test
    @DisplayName("Should detect GitHub Actions environment")
    void testIsAvailableWhenEnvSet() {
        assertTrue(integration.isAvailable());
    }

    @Test
    @DisplayName("Should not be available outside GitHub Actions")
    void testIsNotAvailableWithoutEnv() {
        GitHubActionsIntegration notInCi = new GitHubActionsIntegration(
                new PrintStream(new ByteArrayOutputStream()), Map.of());
        assertFalse(notInCi.isAvailable());
    }

    @Test
    @DisplayName("Should emit ::error:: annotations for CRITICAL findings")
    void testEmitsCriticalAnnotation() {
        integration.initialize(new ScanConfig());
        Finding critical = makeFinding("SQL Injection", Severity.CRITICAL);
        ScanResult result = new ScanResult("https://api.example.com", List.of(critical));

        integration.processResults(result);

        String output = outputCapture.toString();
        assertTrue(output.contains("::error"), "CRITICAL should produce ::error annotation");
        assertTrue(output.contains("SQL Injection"), "Annotation should contain finding title");
    }

    @Test
    @DisplayName("Should emit ::warning:: annotations for MEDIUM findings")
    void testEmitsMediumAnnotation() {
        integration.initialize(new ScanConfig());
        Finding medium = makeFinding("Verbose Error", Severity.MEDIUM);
        ScanResult result = new ScanResult("https://api.example.com", List.of(medium));

        integration.processResults(result);

        String output = outputCapture.toString();
        assertTrue(output.contains("::warning"), "MEDIUM should produce ::warning annotation");
    }

    @Test
    @DisplayName("Should emit ::notice:: annotations for LOW findings")
    void testEmitsNoticeAnnotation() {
        integration.initialize(new ScanConfig());
        Finding low = makeFinding("Missing Header", Severity.LOW);
        ScanResult result = new ScanResult("https://api.example.com", List.of(low));

        integration.processResults(result);

        String output = outputCapture.toString();
        assertTrue(output.contains("::notice"), "LOW should produce ::notice annotation");
    }

    @Test
    @DisplayName("Should build PR comment body with summary table")
    void testBuildPrCommentBody() {
        Finding critical = makeFinding("Auth Bypass", Severity.CRITICAL);
        Finding high = makeFinding("IDOR", Severity.HIGH);
        ScanResult result = new ScanResult("https://api.example.com", List.of(critical, high));

        String body = integration.buildPrCommentBody(result);

        assertTrue(body.contains("OWASP API Security Testing Framework Results"));
        assertTrue(body.contains("Total Findings: 2") || body.contains("**Total Findings:** 2"));
        assertTrue(body.contains("CRITICAL"));
        assertTrue(body.contains("HIGH"));
        assertTrue(body.contains("Auth Bypass"));
        assertTrue(body.contains("IDOR"));
    }

    @Test
    @DisplayName("Should produce empty annotations for empty scan results")
    void testNoAnnotationsForEmptyResults() {
        integration.initialize(new ScanConfig());
        ScanResult result = new ScanResult("https://api.example.com", List.of());

        integration.processResults(result);

        String output = outputCapture.toString();
        assertFalse(output.contains("::error"), "No annotations expected for empty results");
        assertFalse(output.contains("::warning"), "No annotations expected for empty results");
    }

    @Test
    @DisplayName("Should initialize without throwing")
    void testInitialize() {
        ScanConfig config = new ScanConfig();
        config.setTargetUrl("https://api.example.com");
        assertDoesNotThrow(() -> integration.initialize(config));
    }

    private Finding makeFinding(String title, Severity severity) {
        return new Finding(UUID.randomUUID().toString(), title, "Description of " + title,
                severity, "ASTF-API1-2023", "GET /api/test", "Apply fix.");
    }
}
