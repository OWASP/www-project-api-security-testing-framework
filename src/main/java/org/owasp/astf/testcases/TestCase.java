package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;

/**
 * Interface for all API security test cases.
 */
public interface TestCase {
    /**
     * Get the unique identifier for this test case.
     *
     * @return The test case ID
     */
    String getId();

    /**
     * Get the name of this test case.
     *
     * @return The test case name
     */
    String getName();

    /**
     * Get the description of this test case.
     *
     * @return The test case description
     */
    String getDescription();

    /**
     * Execute this test case against the specified endpoint.
     *
     * @param endpoint The endpoint to test
     * @param httpClient The HTTP client to use
     * @return A list of findings, or an empty list if no issues were found
     * @throws IOException If the test execution fails
     */
    List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException;
}