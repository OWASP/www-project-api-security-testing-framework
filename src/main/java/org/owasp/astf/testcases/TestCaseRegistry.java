package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;

/**
 * Registry for all available test cases.
 */
public class TestCaseRegistry {
    private static final Logger logger = LogManager.getLogger(TestCaseRegistry.class);

    private final List<TestCase> availableTestCases;

    public TestCaseRegistry() {
        this.availableTestCases = new ArrayList<>();
        registerDefaultTestCases();
    }

    /**
     * Registers all default test cases.
     */
    private void registerDefaultTestCases() {
        // OWASP API Security Top 10
       // Register all the test cases here
    }

    /**
     * Registers a test case.
     *
     * @param testCase The test case to register
     */
    public void register(TestCase testCase) {
        availableTestCases.add(testCase);
        logger.debug("Registered test case: {}", testCase.getId());
    }

    /**
     * Gets all registered test cases.
     *
     * @return All registered test cases
     */
    public List<TestCase> getAllTestCases() {
        return new ArrayList<>(availableTestCases);
    }

    /**
     * Gets test cases that are enabled based on the scan configuration.
     *
     * @param config The scan configuration
     * @return Enabled test cases
     */
    public List<TestCase> getEnabledTestCases(ScanConfig config) {
        List<String> enabledIds = config.getEnabledTestCaseIds();
        List<String> disabledIds = config.getDisabledTestCaseIds();

        // If specific test cases are enabled, use only those
        if (!enabledIds.isEmpty()) {
            return availableTestCases.stream()
                    .filter(tc -> enabledIds.contains(tc.getId()))
                    .collect(Collectors.toList());
        }

        // Otherwise, use all except those specifically disabled
        return availableTestCases.stream()
                .filter(tc -> !disabledIds.contains(tc.getId()))
                .collect(Collectors.toList());
    }
}