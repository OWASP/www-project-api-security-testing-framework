package org.owasp.astf.testcases;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("RegexDosTestCase unit tests")
class RegexDosTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private RegexDosTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new RegexDosTestCase();
    }

    @Test
    @DisplayName("getId / getName / getDescription return expected values")
    void testMetadata() {
        assertEquals("ASTF-REDOS-2023", testCase.getId());
        assertEquals("Regular Expression Denial of Service (ReDoS)", testCase.getName());
        assertNotNull(testCase.getDescription());
    }

    @Test
    @DisplayName("Skips GET endpoints entirely — ReDoS only tested against body-carrying methods")
    void testSkipsGetEndpoints() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users", "GET");
        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Does not flag ReDoS when every response is fast")
    void testNoFindingWhenFast() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1/email", "PUT", "application/json",
                "{\"email\":\"a@b.com\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{\"updated\":true}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty());
    }

    @Test
    @DisplayName("Detects ReDoS when the payload request times out (SocketTimeoutException)")
    void testDetectsReDosViaTimeout() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1/email", "PUT", "application/json",
                "{\"email\":\"a@b.com\"}", true);
        endpoint.setBaseUrl("https://example.com");

        // Baseline (benign "test" value) succeeds fast; any call containing the long ReDoS
        // payload (35 repeated characters) times out instead.
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && !body.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        && !body.contains("11111111111111111111111111111111111"))))
                .thenReturn(new HttpResponse(200, "{\"updated\":true}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(),
                argThat(body -> body != null && (body.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                        || body.contains("11111111111111111111111111111111111")))))
                .thenThrow(new SocketTimeoutException("Read timed out"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should detect ReDoS from the timeout");
        assertEquals("Regular Expression Denial of Service (ReDoS)", findings.get(0).getTitle());
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("Handles exceptions gracefully when the baseline request itself fails")
    void testHandlesBaselineFailureGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1/email", "PUT", "application/json",
                "{\"email\":\"a@b.com\"}", true);
        endpoint.setBaseUrl("https://example.com");

        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.isEmpty(), "Should skip gracefully when even the baseline can't be established");
    }

    private static boolean isRedosPayload(String body) {
        return body != null && (body.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                || body.contains("11111111111111111111111111111111111"));
    }

    private EndpointInfo putEndpoint() {
        EndpointInfo endpoint = new EndpointInfo("/api/users/1/email", "PUT", "application/json",
                "{\"email\":\"a@b.com\"}", true);
        endpoint.setBaseUrl("https://example.com");
        return endpoint;
    }

    @Test
    @DisplayName("ConnectException on a payload request is not reported as ReDoS")
    void testConnectExceptionIsNotReDos() throws IOException {
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(b -> !isRedosPayload(b))))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(RegexDosTestCaseTest::isRedosPayload)))
                .thenThrow(new ConnectException("Connection refused"));

        assertTrue(testCase.execute(putEndpoint(), httpClient).isEmpty());
    }

    @Test
    @DisplayName("Non-timeout IOException (connection reset) is not reported as ReDoS")
    void testConnectionResetIsNotReDos() throws IOException {
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(b -> !isRedosPayload(b))))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(RegexDosTestCaseTest::isRedosPayload)))
                .thenThrow(new IOException("Connection reset"));

        assertTrue(testCase.execute(putEndpoint(), httpClient).isEmpty());
    }

    @Test
    @DisplayName("Interrupted request yields no finding and preserves the interrupt flag")
    void testInterruptedIsNotReDos() throws IOException {
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(b -> !isRedosPayload(b))))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(RegexDosTestCaseTest::isRedosPayload)))
                .thenAnswer(inv -> {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("interrupted");
                });

        try {
            assertTrue(testCase.execute(putEndpoint(), httpClient).isEmpty());
            assertTrue(Thread.currentThread().isInterrupted(), "Interrupt flag must be preserved");
        } finally {
            Thread.interrupted(); // clear so later tests are unaffected
        }
    }

    @Test
    @DisplayName("Timeout right after a healthy baseline check yields the HIGH finding")
    void testTimeoutAfterHealthyBaselineFlags() throws IOException {
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(b -> !isRedosPayload(b))))
                .thenReturn(new HttpResponse(200, "{}", Map.of()));
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), argThat(RegexDosTestCaseTest::isRedosPayload)))
                .thenThrow(new SocketTimeoutException("Read timed out"));

        List<Finding> findings = testCase.execute(putEndpoint(), httpClient);
        assertEquals(1, findings.size());
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("A real ReDoS that leaves the server hung is still reported (single-threaded target, e.g. VAmPI)")
    void testHungServerAfterRealReDosIsStillReported() throws IOException {
        // Baseline and the pre-payload health check are answered, the payload hangs the server, and
        // every request after that also times out because the server is stuck in the regex.
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()))
                .thenThrow(new SocketTimeoutException("Read timed out"));

        List<Finding> findings = testCase.execute(putEndpoint(), httpClient);

        assertEquals(1, findings.size(), "the hang caused by the payload is the finding, not a reason to discard it");
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("A target that is not answering the baseline before the payload is not tested or reported")
    void testUnhealthyTargetBeforePayloadIsNotReDos() throws IOException {
        // Baseline succeeds once, then the target goes down: the health check before each payload fails.
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()))
                .thenThrow(new SocketTimeoutException("Read timed out"));

        assertTrue(testCase.execute(putEndpoint(), httpClient).isEmpty());
        verify(httpClient, never()).putWithStatus(anyString(), anyMap(), anyString(),
                argThat(RegexDosTestCaseTest::isRedosPayload));
    }

    @Test
    @DisplayName("A baseline that answers but slower than the threshold before the payload is not a healthy target")
    void testSlowBaselineBeforePayloadIsNotReDos() throws IOException {
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()))             // baseline
                .thenAnswer(inv -> {                                          // slow health check: skip payload 1
                    Thread.sleep(4300);
                    return new HttpResponse(200, "{}", Map.of());
                })
                .thenReturn(new HttpResponse(200, "{}", Map.of()));            // everything after is fast and fine

        assertTrue(testCase.execute(putEndpoint(), httpClient).isEmpty());
    }

    @Test
    @DisplayName("An unhealthy check before one payload skips only that payload: later payloads are still tested")
    void testUnhealthyCheckDoesNotStopTestingOtherPayloads() throws IOException {
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()))          // baseline
                .thenThrow(new IOException("Connection refused"))           // health check 1 fails: payload 1 skipped
                .thenReturn(new HttpResponse(200, "{}", Map.of()))          // health check 2 passes
                .thenThrow(new SocketTimeoutException("Read timed out"));   // payload 2 hangs: reported

        List<Finding> findings = testCase.execute(putEndpoint(), httpClient);

        assertEquals(1, findings.size(), "the second payload must still be tested and reported");
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    @DisplayName("A socket timeout on the health check skips only that payload and does not mark the thread interrupted")
    void testHealthCheckTimeoutIsNotACancellation() throws IOException {
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200, "{}", Map.of()))              // baseline
                .thenThrow(new SocketTimeoutException("Read timed out"))        // health check 1 times out
                .thenReturn(new HttpResponse(200, "{}", Map.of()))              // health check 2 passes
                .thenThrow(new SocketTimeoutException("Read timed out"));       // payload 2 hangs

        List<Finding> findings = testCase.execute(putEndpoint(), httpClient);

        assertFalse(Thread.interrupted(), "an ordinary timeout must not set the interrupt flag");
        assertEquals(1, findings.size(), "testing must continue after the health check timed out");
    }

    @Test
    @DisplayName("A slow health check before the first payload means exactly one payload fewer is sent")
    void testSlowHealthCheckSkipsExactlyOnePayload() throws IOException {
        List<String> slowRunBodies = new java.util.ArrayList<>();
        java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        when(httpClient.putWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            slowRunBodies.add(inv.getArgument(3));
            if (calls.incrementAndGet() == 2) {          // the first health check is slower than the threshold
                Thread.sleep(4300);
            }
            return new HttpResponse(200, "{}", Map.of());
        });
        assertTrue(testCase.execute(putEndpoint(), httpClient).isEmpty());
        long slowPayloads = slowRunBodies.stream().filter(RegexDosTestCaseTest::isRedosPayload).count();

        HttpClient fastClient = org.mockito.Mockito.mock(HttpClient.class);
        List<String> fastRunBodies = new java.util.ArrayList<>();
        when(fastClient.putWithStatus(anyString(), anyMap(), anyString(), anyString())).thenAnswer(inv -> {
            fastRunBodies.add(inv.getArgument(3));
            return new HttpResponse(200, "{}", Map.of());
        });
        new RegexDosTestCase().execute(putEndpoint(), fastClient);
        long fastPayloads = fastRunBodies.stream().filter(RegexDosTestCaseTest::isRedosPayload).count();

        assertEquals(fastPayloads - 1, slowPayloads, "only the payload after the slow check is skipped");
    }
}
