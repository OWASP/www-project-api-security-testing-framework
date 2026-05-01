package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("TestCaseRegistry Tests")
class TestCaseRegistryTest {

    private TestCaseRegistry registry;
    private ScanConfig config;

    @BeforeEach
    void setUp() {
        registry = new TestCaseRegistry();
        config = new ScanConfig();
    }

    @Test
    @DisplayName("Should register all 10 OWASP API Security Top 10 test cases by default")
    void testDefaultRegistration() {
        List<TestCase> testCases = registry.getAllTestCases();
        assertEquals(10, testCases.size(), "Should have 10 default test cases");
    }

    @Test
    @DisplayName("Should register all expected OWASP test case IDs")
    void testExpectedTestCaseIds() {
        List<TestCase> testCases = registry.getAllTestCases();
        List<String> ids = testCases.stream().map(TestCase::getId).toList();

        assertTrue(ids.contains("ASTF-API1-2023"), "Should contain API1");
        assertTrue(ids.contains("ASTF-API2-2023"), "Should contain API2");
        assertTrue(ids.contains("ASTF-API3-2023"), "Should contain API3");
        assertTrue(ids.contains("ASTF-API4-2023"), "Should contain API4");
        assertTrue(ids.contains("ASTF-API5-2023"), "Should contain API5");
        assertTrue(ids.contains("ASTF-API6-2023"), "Should contain API6");
        assertTrue(ids.contains("ASTF-API7-2023"), "Should contain API7");
        assertTrue(ids.contains("ASTF-API8-2023"), "Should contain API8");
        assertTrue(ids.contains("ASTF-API9-2023"), "Should contain API9");
        assertTrue(ids.contains("ASTF-API10-2023"), "Should contain API10");
    }

    @Test
    @DisplayName("Should allow registering additional custom test cases")
    void testCustomRegistration() {
        int before = registry.getAllTestCases().size();
        registry.register(new BrokenAuthenticationTestCase()); // Register a duplicate
        assertEquals(before + 1, registry.getAllTestCases().size());
    }

    @Test
    @DisplayName("Should return all test cases when no enabled/disabled filters set")
    void testGetEnabledNoFilter() {
        List<TestCase> enabled = registry.getEnabledTestCases(config);
        assertEquals(10, enabled.size());
    }

    @Test
    @DisplayName("Should filter to only enabled test cases when enabledTestCaseIds is set")
    void testGetEnabledWithFilter() {
        config.setEnabledTestCaseIds(List.of("ASTF-API1-2023", "ASTF-API2-2023"));
        List<TestCase> enabled = registry.getEnabledTestCases(config);
        assertEquals(2, enabled.size());
        assertTrue(enabled.stream().allMatch(tc ->
                tc.getId().equals("ASTF-API1-2023") || tc.getId().equals("ASTF-API2-2023")));
    }

    @Test
    @DisplayName("Should exclude disabled test cases")
    void testGetEnabledWithDisabled() {
        config.setDisabledTestCaseIds(List.of("ASTF-API1-2023", "ASTF-API2-2023"));
        List<TestCase> enabled = registry.getEnabledTestCases(config);
        assertEquals(8, enabled.size());
        assertTrue(enabled.stream().noneMatch(tc ->
                tc.getId().equals("ASTF-API1-2023") || tc.getId().equals("ASTF-API2-2023")));
    }

    @Test
    @DisplayName("All test cases should have non-null metadata")
    void testAllTestCasesHaveMetadata() {
        for (TestCase tc : registry.getAllTestCases()) {
            assertNotNull(tc.getId(), "Test case ID should not be null");
            assertNotNull(tc.getName(), "Test case name should not be null");
            assertNotNull(tc.getDescription(), "Test case description should not be null");
            assertFalse(tc.getId().isBlank(), "Test case ID should not be blank");
            assertFalse(tc.getName().isBlank(), "Test case name should not be blank");
        }
    }
}
