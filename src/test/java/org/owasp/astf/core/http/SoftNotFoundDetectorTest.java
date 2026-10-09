package org.owasp.astf.core.http;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SoftNotFoundDetector}.
 *
 * <p>The two properties that matter most are asserted in both directions throughout:</p>
 * <ul>
 *   <li><strong>Inertness.</strong> Against a target that answers 404 for unknown paths — the
 *       normal case — the detector must never suppress anything, so adding it to a check cannot
 *       change that check's existing results.</li>
 *   <li><strong>No new false negatives.</strong> Against a target that <em>does</em> have a
 *       catch-all, a response that genuinely differs from the catch-all must still get through.
 *       Silently swallowing a real finding is worse than leaving a false positive in.</li>
 * </ul>
 */
@DisplayName("SoftNotFoundDetector Tests")
class SoftNotFoundDetectorTest {

    private static final String BASE_URL = "https://api.example.com";

    @Mock
    private HttpClient httpClient;

    private SoftNotFoundDetector detector;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        detector = new SoftNotFoundDetector();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static HttpResponse response(int status, String body, String contentType) {
        return contentType == null
                ? new HttpResponse(status, body, Map.of())
                : new HttpResponse(status, body, Map.of("Content-Type", List.of(contentType)));
    }

    private static HttpResponse ok(String body, String contentType) {
        return response(200, body, contentType);
    }

    private static boolean isProbe(String url) {
        return url != null && url.contains("astf-unknown-path-probe");
    }

    /** Target behaves correctly: unknown paths get a real 404. */
    private void targetAnswers404ForUnknownPaths() throws IOException {
        when(httpClient.getWithStatus(argThat(SoftNotFoundDetectorTest::isProbe), anyMap()))
                .thenReturn(response(404, "{\"error\":\"not found\"}", "application/json"));
    }

    /** Target serves the same page for every unknown path. */
    private void targetServesCatchAll(String body, String contentType) throws IOException {
        when(httpClient.getWithStatus(argThat(SoftNotFoundDetectorTest::isProbe), anyMap()))
                .thenReturn(ok(body, contentType));
    }

    // -------------------------------------------------------------------------
    // Inert against a well-behaved target
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Suppresses nothing when the target returns a real 404 for unknown paths")
    void testInertWhenTargetHasNoCatchAll() throws IOException {
        targetAnswers404ForUnknownPaths();

        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok("{\"users\":[]}", "application/json")),
                "A target that 404s unknown paths must not have any of its 2xx responses suppressed");
        assertFalse(detector.hasCatchAllResponses(BASE_URL, httpClient),
                "No catch-all should be reported when probes return 404");
    }

    @Test
    @DisplayName("Suppresses nothing when the baseline probe itself fails")
    void testInertWhenProbeThrows() throws IOException {
        when(httpClient.getWithStatus(anyString(), anyMap()))
                .thenThrow(new IOException("Connection refused"));

        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient, ok("{\"a\":1}", "application/json")),
                "An unusable probe must leave the caller's existing behaviour untouched");
        assertFalse(detector.hasCatchAllResponses(BASE_URL, httpClient));
    }

    @Test
    @DisplayName("Ignores non-success and null responses without probing")
    void testNonSuccessAndNullResponses() {
        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient, response(404, "nope", "text/html")));
        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient, response(500, "boom", "text/html")));
        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient, null));
    }

    @Test
    @DisplayName("Handles a missing base URL without probing")
    void testMissingBaseUrl() {
        HttpResponse real = ok("{\"users\":[]}", "application/json");
        assertFalse(detector.looksLikeUnknownPath(null, httpClient, real));
        assertFalse(detector.looksLikeUnknownPath("   ", httpClient, real));
        assertFalse(detector.hasCatchAllResponses(null, httpClient));
    }

    // -------------------------------------------------------------------------
    // Catch-all targets
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Detects an SPA HTML catch-all and suppresses an identical response")
    void testHtmlSpaCatchAllSuppressed() throws IOException {
        String shell = "<html><head><title>App</title></head><body><div id=\"root\"></div></body></html>";
        targetServesCatchAll(shell, "text/html; charset=utf-8");

        assertTrue(detector.hasCatchAllResponses(BASE_URL, httpClient));
        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient, ok(shell, "text/html")),
                "The app shell served for a guessed path is the catch-all, not a discovery");
    }

    @Test
    @DisplayName("Detects a JSON gateway catch-all and suppresses an identical response")
    void testJsonGatewayCatchAllSuppressed() throws IOException {
        String envelope = "{\"success\":false,\"payload\":null}";
        targetServesCatchAll(envelope, "application/json");

        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient, ok(envelope, "application/json")),
                "A JSON catch-all passes the content-type check, so only the baseline can screen it out");
    }

    @Test
    @DisplayName("Still reports a genuinely different response on a catch-all target (no false negative)")
    void testDifferentResponseStillReportedOnCatchAllTarget() throws IOException {
        targetServesCatchAll("{\"success\":false,\"payload\":null}", "application/json");

        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok("{\"users\":[{\"id\":1,\"role\":\"admin\"}],\"total\":1}", "application/json")),
                "A real endpoint's response differs from the catch-all and must still be reported");
    }

    @Test
    @DisplayName("Does not match across content-type families")
    void testContentTypeFamiliesDoNotCrossMatch() throws IOException {
        targetServesCatchAll("<html><body>App</body></html>", "text/html");

        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient, ok("{\"x\":1}", "application/json")),
                "A JSON response cannot be the same thing as an HTML catch-all page");
    }

    @Test
    @DisplayName("Matches a catch-all whose body carries a rotating token or timestamp")
    void testCatchAllWithVolatileTokenStillMatches() throws IOException {
        targetServesCatchAll(
                "<html><body><input name=\"csrf\" value=\"a1b2c3d4e5f6a7b8\">"
                        + "<span>generated 1737412800</span></body></html>",
                "text/html");

        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok("<html><body><input name=\"csrf\" value=\"99887766554433aa\">"
                                + "<span>generated 1737499200</span></body></html>", "text/html")),
                "A per-request CSRF token or timestamp must not stop a catch-all from matching itself");
    }

    @Test
    @DisplayName("Tolerates small residual variation the normaliser did not mask")
    void testNearlyIdenticalCatchAllMatches() throws IOException {
        String shell = "<html><body><div id=\"root\">Loading the application, please wait...</div></body></html>";
        targetServesCatchAll(shell, "text/html");

        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok(shell.replace("wait...", "wait!!!"), "text/html")),
                "A few characters of drift in an otherwise identical shell is still the same page");
    }

    // -------------------------------------------------------------------------
    // Error-envelope bodies (independent of any baseline)
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Treats a 2xx carrying a numeric 4xx/5xx status in its body as an unknown path")
    void testErrorStatusInBodyOfSuccessResponse() throws IOException {
        targetAnswers404ForUnknownPaths();

        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok("{\"status\":404,\"path\":\"/admin\"}", "application/json")),
                "No real endpoint reports its own absence with a success status");
    }

    @Test
    @DisplayName("Treats a 2xx 'Not Found' message envelope as an unknown path")
    void testNotFoundMessageInBodyOfSuccessResponse() throws IOException {
        targetAnswers404ForUnknownPaths();

        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                ok("{\"message\":\"Not Found\"}", "application/json")));
        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                ok("{\"detail\":\"The requested resource does not exist\"}", "application/json")));
    }

    @Test
    @DisplayName("Treats an Express-style 'Cannot GET /path' body as an unknown path")
    void testCannotMethodPathBody() throws IOException {
        targetAnswers404ForUnknownPaths();

        assertTrue(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok("<pre>Cannot GET /admin</pre>", "text/html")),
                "Express and friends answer unknown routes with this body");
    }

    @Test
    @DisplayName("Does not mistake a health payload's string status for an error status")
    void testHealthPayloadIsNotAnErrorEnvelope() throws IOException {
        targetAnswers404ForUnknownPaths();

        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok("{\"status\":\"UP\",\"diskSpace\":{\"total\":500}}", "application/json")),
                "A quoted status value is not an HTTP error code — actuator payloads must survive");
    }

    @Test
    @DisplayName("Does not treat an ordinary body mentioning 'error' as an unknown path")
    void testOrdinaryBodyMentioningErrorIsNotSuppressed() throws IOException {
        targetAnswers404ForUnknownPaths();

        assertFalse(detector.looksLikeUnknownPath(BASE_URL, httpClient,
                        ok("{\"error\":\"invalid credentials\",\"attempts\":2}", "application/json")),
                "Only wording that announces the resource is absent counts, not the word 'error'");
    }

    @Test
    @DisplayName("looksLikeNotFoundBody handles blank and null input")
    void testLooksLikeNotFoundBodyEdgeCases() {
        assertFalse(SoftNotFoundDetector.looksLikeNotFoundBody(null));
        assertFalse(SoftNotFoundDetector.looksLikeNotFoundBody(""));
        assertFalse(SoftNotFoundDetector.looksLikeNotFoundBody("   "));
        assertTrue(SoftNotFoundDetector.looksLikeNotFoundBody("{\"code\": 500}"));
    }

    // -------------------------------------------------------------------------
    // Probe cost
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Probes a target once and reuses the baseline for every later response")
    void testBaselineIsCachedPerBaseUrl() throws IOException {
        targetServesCatchAll("<html><body>App</body></html>", "text/html");

        for (int i = 0; i < 25; i++) {
            detector.looksLikeUnknownPath(BASE_URL, httpClient, ok("<html><body>App</body></html>", "text/html"));
        }
        detector.hasCatchAllResponses(BASE_URL, httpClient);

        verify(httpClient, times(2))
                .getWithStatus(argThat(SoftNotFoundDetectorTest::isProbe), anyMap());
    }

    @Test
    @DisplayName("Probes the root and a nested path, since a catch-all may cover only one shape")
    void testProbesBothPathShapes() throws IOException {
        targetAnswers404ForUnknownPaths();
        detector.hasCatchAllResponses(BASE_URL, httpClient);

        verify(httpClient).getWithStatus(
                argThat(url -> isProbe(url) && url.endsWith(".json")), anyMap());
        verify(httpClient).getWithStatus(
                argThat(url -> isProbe(url) && !url.endsWith(".json")), anyMap());
    }

    @Test
    @DisplayName("Does not double up the slash when the base URL has a trailing one")
    void testTrailingSlashInBaseUrl() throws IOException {
        targetAnswers404ForUnknownPaths();
        detector.hasCatchAllResponses(BASE_URL + "/", httpClient);

        verify(httpClient, times(2)).getWithStatus(
                argThat(url -> isProbe(url) && !url.contains("com//")), anyMap());
    }

    // -------------------------------------------------------------------------
    // Body normalisation
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("normalizeBody masks volatile tokens, digits and whitespace")
    void testNormalizeBody() {
        assertEquals("", SoftNotFoundDetector.normalizeBody(null));
        assertEquals("", SoftNotFoundDetector.normalizeBody("   \n\t "));
        assertEquals(SoftNotFoundDetector.normalizeBody("id=deadbeefcafe0001"),
                SoftNotFoundDetector.normalizeBody("id=0123456789abcdef"));
        assertEquals(SoftNotFoundDetector.normalizeBody("<p>Hello   World</p>"),
                SoftNotFoundDetector.normalizeBody("<p>Hello\n\tWorld</p>"));
        assertEquals(SoftNotFoundDetector.normalizeBody("<p>HELLO</p>"),
                SoftNotFoundDetector.normalizeBody("<p>hello</p>"));
    }

    // -------------------------------------------------------------------------
    // Shared isApiResponse (behaviour must stay identical to the copies it replaced)
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("isApiResponse rejects HTML and accepts structured data")
    void testIsApiResponseContentTypes() {
        assertFalse(SoftNotFoundDetector.isApiResponse(ok("<html></html>", "text/html; charset=utf-8")));
        assertTrue(SoftNotFoundDetector.isApiResponse(ok("{}", "application/json")));
        assertTrue(SoftNotFoundDetector.isApiResponse(ok("<root/>", "application/xml")));
        assertTrue(SoftNotFoundDetector.isApiResponse(ok("plain", "text/plain")));
    }

    @Test
    @DisplayName("isApiResponse falls back to body sniffing without a usable Content-Type")
    void testIsApiResponseBodySniffing() {
        assertTrue(SoftNotFoundDetector.isApiResponse(ok("  {\"a\":1}", null)));
        assertTrue(SoftNotFoundDetector.isApiResponse(ok("[1,2,3]", null)));
        assertFalse(SoftNotFoundDetector.isApiResponse(ok("<html></html>", null)));
        assertFalse(SoftNotFoundDetector.isApiResponse(ok("", null)));
        assertTrue(SoftNotFoundDetector.isApiResponse(ok("{\"a\":1}", "application/octet-stream")));
    }

    @Test
    @DisplayName("isApiResponse handles a null response")
    void testIsApiResponseNull() {
        assertFalse(SoftNotFoundDetector.isApiResponse(null));
    }
}
