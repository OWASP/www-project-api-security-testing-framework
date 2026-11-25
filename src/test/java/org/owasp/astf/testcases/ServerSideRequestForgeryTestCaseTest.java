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
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

import org.mockito.ArgumentCaptor;

/**
 * Unit tests for {@link ServerSideRequestForgeryTestCase} (OWASP API7:2023).
 */
@DisplayName("Server Side Request Forgery Test Case Tests")
class ServerSideRequestForgeryTestCaseTest {

    @Mock
    private HttpClient httpClient;

    private ServerSideRequestForgeryTestCase testCase;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        testCase = new ServerSideRequestForgeryTestCase();
    }

    // -------------------------------------------------------------------------
    // Helper factories
    // -------------------------------------------------------------------------

    private static HttpResponse ok() {
        return new HttpResponse(200, "{\"data\":\"ok\"}", Map.of());
    }

    private static HttpResponse notFound() {
        return new HttpResponse(404, "{}", Map.of());
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should have correct ID and name")
    void testMetadata() {
        assertEquals("ASTF-API7-2023", testCase.getId());
        assertEquals("Server Side Request Forgery", testCase.getName());
    }

    @Test
    @DisplayName("Should detect SSRF when GET response body contains AWS metadata indicator 'ami-id'")
    void testSsrfDetectedInQueryParam() throws IOException {
        // GET endpoint — the test case exercises testQueryParameterSsrf
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        // Baseline (no injected params, URL has no "=") is clean; only the payload-bearing
        // probe URLs (which always append "?param=...") return the SSRF indicator.
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(200,
                        "{\"result\":\"ami-id: ami-0abcdef1234567890\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report a finding when SSRF indicator is in the response");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("SSRF")
                        || f.getTitle().contains("Server Side Request Forgery")),
                "Finding title should reference SSRF");
    }

    @Test
    @DisplayName("Should NOT flag SSRF when the indicator is already present in the baseline (unmodified) response")
    void testNoSsrfWhenIndicatorAlreadyInBaseline() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        // Every response — baseline AND payload-probe alike — mentions "docker", simulating an
        // API that just happens to describe its own deployment environment. Since the word is
        // already present without any injected payload, it must not be treated as SSRF evidence.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"platform\":\"docker\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(),
                "Should not flag SSRF when the indicator word is already present in the endpoint's normal response");
    }

    @Test
    @DisplayName("Should return no findings when GET response body is clean (no SSRF indicators)")
    void testNoSsrfWhenResponseClean() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"normal\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not report findings when response contains no SSRF indicators");
    }

    @Test
    @DisplayName("Should detect SSRF when POST response body contains 'instance-id'")
    void testSsrfDetectedInBodyParam() throws IOException {
        // POST endpoint — exercises testBodyParameterSsrf
        EndpointInfo endpoint = new EndpointInfo("/api/proxy", "POST");

        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"response\":\"instance-id: i-1234567890abcdef0\"}",
                        Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertFalse(findings.isEmpty(), "Should report a finding when SSRF indicator is in the POST response");
        assertTrue(
                findings.stream().anyMatch(f -> f.getTitle().contains("SSRF")
                        || f.getTitle().contains("Server Side Request Forgery")),
                "Finding title should reference SSRF");
    }

    @Test
    @DisplayName("Should return no findings when POST returns 403 (server rejects SSRF payload)")
    void testSsrfNotDetectedWhenServerRejects() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/proxy", "POST");

        // Server rejects the request — no SSRF content is returned
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(403, "{\"error\":\"forbidden\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "Should not report findings when server rejects the SSRF payload");
    }

    @Test
    @DisplayName("Should handle IOException gracefully and not propagate the exception")
    void testExceptionHandledGracefully() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        List<Finding> findings = assertDoesNotThrow(() -> testCase.execute(endpoint, httpClient));
        assertNotNull(findings);
    }

    @Test
    @DisplayName("Should NOT flag a GET endpoint that echoes the injected URL (payload contains 'computeMetadata')")
    void testNoFindingWhenGetEndpointEchoesPayload() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/echo", "GET");

        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        // Reflect the (URL-encoded) query value back, as an echo API would.
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("=")), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    String value = url.substring(url.indexOf('=') + 1);
                    String decoded = java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8);
                    return new HttpResponse(200, "{\"you_sent\":\"" + decoded + "\"}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "An API that only reflects the payload must not be reported as SSRF");
    }

    @Test
    @DisplayName("Should NOT flag a POST endpoint that echoes the JSON body (incl. escaped slashes)")
    void testNoFindingWhenPostEndpointEchoesPayload() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/echo", "POST");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenAnswer(inv -> new HttpResponse(200,
                        "{\"received\":" + ((String) inv.getArgument(3)).replace("/", "\\/") + "}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.isEmpty(), "A body echo must not be reported as SSRF");
    }

    @Test
    @DisplayName("A non-2xx response with an indicator is never CRITICAL, only a MEDIUM possible SSRF (not dropped)")
    void testNon2xxIndicatorIsOnlyPossibleSsrf() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(400, "{\"error\":\"bad instance-id\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);
        assertTrue(findings.stream().noneMatch(f -> f.getSeverity() == Severity.CRITICAL));
        assertTrue(findings.stream().allMatch(f -> f.getSeverity() == Severity.MEDIUM
                && f.getTitle().startsWith("Possible Server Side Request Forgery")));
    }

    @Test
    @DisplayName("Metadata relayed with a 502 by a proxy is still reported (as possible SSRF), not dropped")
    void testRelayedMetadataWithNon2xxIsReported() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(502, "ami-id\nami-launch-index\nhostname\ninstance-id\n", Map.of()));

        assertFalse(testCase.execute(endpoint, httpClient).isEmpty());
    }

    @Test
    @DisplayName("Should still flag genuine metadata content that is not part of the payload, even when the payload is echoed too")
    void testStillDetectsRealMetadataAlongsideEcho() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "GET");

        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("=")), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    String value = url.substring(url.indexOf('=') + 1);
                    String decoded = java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8);
                    return new HttpResponse(200, "{\"url\":\"" + decoded + "\",\"body\":"
                            + "{\"instance-id\":\"i-0abc123\",\"iam\":{\"AccessKeyId\":\"ASIA...\"}}}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertEquals(1, findings.size());
    }

    @Test
    @DisplayName("Content that changes during the scan (crAPI recent posts) is not reported; a later real hit still is")
    void testContentChangedDuringScanIsNotSsrf() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/community/posts/recent", "GET");
        java.util.concurrent.atomic.AtomicInteger baselineCalls = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger payloadCalls = new java.util.concurrent.atomic.AtomicInteger();

        // First baseline: no indicator. Later baselines: another check has posted text containing "docker".
        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("=")), anyMap())).thenAnswer(inv ->
                baselineCalls.incrementAndGet() == 1
                        ? new HttpResponse(200, "{\"posts\":[\"hello\"]}", Map.of())
                        : new HttpResponse(200, "{\"posts\":[\"hello\",\"we run docker\"]}", Map.of()));
        // First probe sees the new post; a later probe gets real metadata back.
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("=")), anyMap())).thenAnswer(inv ->
                payloadCalls.incrementAndGet() == 1
                        ? new HttpResponse(200, "{\"posts\":[\"hello\",\"we run docker\"]}", Map.of())
                        : new HttpResponse(200, "ami-id\ninstance-id\n", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertEquals(1, findings.size(), "the changed content is skipped, the later metadata hit is reported");
        assertEquals(Severity.CRITICAL, findings.get(0).getSeverity());
        assertTrue(findings.get(0).getEvidence().contains("'ami-id'"), findings.get(0).getEvidence());
    }
    @Test
    @DisplayName("Discovered JSON body fields are kept; payload is substituted into URL-shaped fields")
    void testBodyProbeKeepsDiscoveredFieldsAndInjectsUrlShaped() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/import", "POST", "application/json",
                "{\"name\":\"report\",\"callback\":\"https://example.com/hook\",\"limit\":10}", true);

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), bodyCaptor.capture()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));

        testCase.execute(endpoint, httpClient);

        assertFalse(bodyCaptor.getAllValues().isEmpty());
        String first = bodyCaptor.getAllValues().get(0);
        assertTrue(first.contains("\"name\""), "non-URL field must be kept: " + first);
        assertTrue(first.contains("\"limit\""), "non-URL field must be kept: " + first);
        assertTrue(first.contains("169.254.169.254") || first.contains("metadata.google.internal")
                        || first.contains("127.0.0.1") || first.contains("localhost"),
                "URL-shaped callback must receive an SSRF payload: " + first);
        assertTrue(first.contains("\"callback\""), "callback field name must remain: " + first);
    }

    @Test
    @DisplayName("When discovered body has no URL-shaped fields, each URL parameter name is added rather than replacing the body")
    void testBodyProbeAddsUrlFieldWhenNoneExist() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/widgets", "POST", "application/json",
                "{\"name\":\"widget\",\"qty\":2}", true);

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), bodyCaptor.capture()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));

        testCase.execute(endpoint, httpClient);

        String first = bodyCaptor.getAllValues().get(0);
        assertTrue(first.contains("\"name\""), "original fields must remain: " + first);
        assertTrue(first.contains("\"qty\""), "original fields must remain: " + first);
        assertTrue(first.contains("\"url\""), "url field must be added: " + first);
        assertTrue(bodyCaptor.getAllValues().stream().anyMatch(b ->
                        b.contains("\"webhook\"") && b.contains("\"name\"") && b.contains("\"qty\"")),
                "every URL parameter name is still tried, each alongside the discovered fields");
    }

    @Test
    @DisplayName("No-body endpoint still gets the historical single-field probe")
    void testNoBodyEndpointStillUsesSingleFieldProbe() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/proxy", "POST");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), bodyCaptor.capture()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));

        testCase.execute(endpoint, httpClient);

        assertFalse(bodyCaptor.getAllValues().isEmpty());
        String first = bodyCaptor.getAllValues().get(0);
        // Historical behaviour: a single JSON field whose value is the payload
        assertTrue(first.matches("\\{\"[^\"]+\":\"http[^\"]+\"\\}"),
                "no-body endpoint must use single-field probe, got: " + first);
    }

    @Test
    @DisplayName("String values that look like http(s) URLs are substituted even when the field name is not URL-shaped")
    void testHttpUrlValuedFieldsAreSubstituted() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/fetch", "POST", "application/json",
                "{\"title\":\"x\",\"remote\":\"https://cdn.example.com/a.png\"}", true);

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), bodyCaptor.capture()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));

        testCase.execute(endpoint, httpClient);

        String first = bodyCaptor.getAllValues().get(0);
        assertTrue(first.contains("\"title\""), "title must be kept: " + first);
        assertTrue(first.contains("\"remote\""), "remote key must remain: " + first);
        assertFalse(first.contains("cdn.example.com"),
                "http(s) value must be replaced with the SSRF payload: " + first);
    }

    @Test
    @DisplayName("GCP Missing Metadata-Flavor header response is HIGH metadata-reached finding")
    void testGcpMetadataHeaderRequiredIsHigh() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/proxy", "POST");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(403,
                        "Missing Metadata-Flavor:Google header", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                        f.getSeverity() == Severity.HIGH
                                && f.getTitle().contains("metadata service reached, header required")),
                "GCP metadata header-required error must be HIGH: " + findings);
    }

    @Test
    @DisplayName("Azure Required metadata header response is HIGH metadata-reached finding")
    void testAzureMetadataHeaderRequiredIsHigh() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/proxy", "POST");

        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(400,
                        "Required metadata header not specified", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().anyMatch(f ->
                        f.getSeverity() == Severity.HIGH
                                && f.getTitle().contains("metadata service reached, header required")),
                "Azure metadata header-required error must be HIGH: " + findings);
    }

    @Test
    @DisplayName("Metadata-header indicator already in the baseline is not reported")
    void testMetadataHeaderIndicatorNotMatchedWhenInBaseline() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/echo", "POST");

        // Baseline and every probe response already contain the GCP header-required phrase —
        // it is part of the endpoint's normal content, not evidence of a new metadata fetch.
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenReturn(new HttpResponse(200,
                        "{\"note\":\"Missing Metadata-Flavor:Google header\"}", Map.of()));
        when(httpClient.postWithStatus(anyString(), anyMap(), anyString(), anyString()))
                .thenReturn(new HttpResponse(200,
                        "{\"note\":\"Missing Metadata-Flavor:Google header\"}", Map.of()));

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("metadata service reached")),
                "Indicator already in the baseline must not produce a finding");
    }

    @Test
    @DisplayName("Metadata-header phrase that only appears because the payload was echoed is not reported")
    void testMetadataHeaderIndicatorNotMatchedWhenOnlyPayloadEcho() throws IOException {
        EndpointInfo endpoint = new EndpointInfo("/api/echo", "GET");

        when(httpClient.getWithStatus(argThat(url -> url != null && !url.contains("=")), anyMap()))
                .thenReturn(new HttpResponse(200, "{\"data\":\"ok\"}", Map.of()));
        // Reflect a note that happens to contain the indicator text after echoing the (URL-encoded)
        // query value — stripPayloadEchoes removes the payload forms; remaining text must not
        // alone be enough unless the indicator survives outside the echo. Here the whole response
        // is only the echoed URL, which contains no metadata-header phrase.
        when(httpClient.getWithStatus(argThat(url -> url != null && url.contains("=")), anyMap()))
                .thenAnswer(inv -> {
                    String url = inv.getArgument(0);
                    String value = url.substring(url.indexOf('=') + 1);
                    String decoded = java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8);
                    return new HttpResponse(200, "{\"you_sent\":\"" + decoded + "\"}", Map.of());
                });

        List<Finding> findings = testCase.execute(endpoint, httpClient);

        assertTrue(findings.stream().noneMatch(f -> f.getTitle().contains("metadata service reached")),
                "A pure payload echo must not produce a metadata-header finding");
    }
}
