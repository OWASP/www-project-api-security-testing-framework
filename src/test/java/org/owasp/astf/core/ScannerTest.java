package org.owasp.astf.core;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Scanner Tests")
class ScannerTest {

    private MockWebServer server;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        // Return 401 by default so test cases don't produce false findings
        server.setDispatcher(new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(@NotNull RecordedRequest request) {
                return new MockResponse()
                        .setResponseCode(401)
                        .setBody("{\"error\":\"unauthorized\"}");
            }
        });
        server.start();
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    @Test
    @DisplayName("Should complete scan and return a non-null result")
    void testScanReturnsResult() {
        ScanConfig config = buildConfig();
        config.addEndpoint(new EndpointInfo("/api/users", "GET"));

        ScanResult result = new Scanner(config).scan();

        assertNotNull(result);
        assertNotNull(result.getTargetUrl());
        assertNotNull(result.getScanStartTime());
        assertNotNull(result.getScanEndTime());
    }

    @Test
    @DisplayName("Should record target URL in result")
    void testResultTargetUrl() {
        ScanConfig config = buildConfig();
        config.addEndpoint(new EndpointInfo("/api/users", "GET"));

        ScanResult result = new Scanner(config).scan();

        assertEquals(config.getTargetUrl(), result.getTargetUrl());
    }

    @Test
    @DisplayName("Should return zero findings when server rejects all requests")
    void testNoFindingsWhenServerRejectsAll() {
        ScanConfig config = buildConfig();
        config.addEndpoint(new EndpointInfo("/api/users", "GET"));
        // Run only the missing-auth test case to keep the test fast
        config.setEnabledTestCaseIds(List.of("ASTF-API2-2023"));

        ScanResult result = new Scanner(config).scan();

        assertEquals(0, result.getTotalFindingsCount(),
                "No findings expected when server returns 401 for every request");
    }

    @Test
    @DisplayName("Should return empty result when no endpoints are configured")
    void testEmptyResultWithNoEndpoints() {
        ScanConfig config = buildConfig();
        // discovery disabled and no explicit endpoints

        ScanResult result = new Scanner(config).scan();

        assertNotNull(result);
        assertEquals(0, result.getTotalFindingsCount());
    }

    @Test
    @DisplayName("Should scan multiple endpoints")
    void testMultipleEndpoints() {
        ScanConfig config = buildConfig();
        config.addEndpoint(new EndpointInfo("/api/users", "GET"));
        config.addEndpoint(new EndpointInfo("/api/products", "GET"));
        config.addEndpoint(new EndpointInfo("/api/orders", "GET"));
        config.setEnabledTestCaseIds(List.of("ASTF-API2-2023"));

        ScanResult result = new Scanner(config).scan();

        assertNotNull(result);
        assertNotNull(result.getScanStartTime());
        assertTrue(result.getScanEndTime().isAfter(result.getScanStartTime())
                || result.getScanEndTime().isEqual(result.getScanStartTime()));
    }

    @Test
    @DisplayName("Should respect disabled test case list")
    void testDisabledTestCases() {
        ScanConfig config = buildConfig();
        config.addEndpoint(new EndpointInfo("/api/users", "GET"));
        // Disable ALL test cases
        config.setDisabledTestCaseIds(List.of(
                "ASTF-API1-2023", "ASTF-API2-2023", "ASTF-API3-2023",
                "ASTF-API4-2023", "ASTF-API5-2023", "ASTF-API6-2023",
                "ASTF-API7-2023", "ASTF-API8-2023", "ASTF-API9-2023",
                "ASTF-API10-2023"));

        ScanResult result = new Scanner(config).scan();

        // With all test cases disabled the scan should still complete and return a result
        assertNotNull(result);
    }

    @Test
    @DisplayName("Should populate severity summary in results")
    void testSeveritySummary() {
        ScanConfig config = buildConfig();
        config.addEndpoint(new EndpointInfo("/api/users", "GET"));
        config.setEnabledTestCaseIds(List.of("ASTF-API2-2023"));

        ScanResult result = new Scanner(config).scan();

        assertNotNull(result.getSeveritySummary());
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private ScanConfig buildConfig() {
        ScanConfig config = new ScanConfig();
        config.setTargetUrl(server.url("").toString());
        config.setDiscoveryEnabled(false);
        config.setTimeoutMinutes(1);
        return config;
    }
}
