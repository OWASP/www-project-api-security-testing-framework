package org.owasp.astf.core.http;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Detects "soft 404" responses — a target replying with HTTP 2xx to paths that don't actually
 * exist.
 *
 * <p>Every test case in this framework that probes for the <em>existence</em> of a path it
 * guessed (admin paths, debug/actuator paths, deprecated API versions, common REST resource
 * names) infers "this exists and is reachable" from a 2xx status. That inference is wrong on the
 * large class of real targets that serve a catch-all response for unknown paths:</p>
 *
 * <ul>
 *   <li>Single-page applications and reverse proxies that return {@code 200 text/html} with the
 *       app shell for every unmatched route, so client-side routing can take over.</li>
 *   <li>API gateways and frameworks configured with a default route that answers {@code 200}
 *       with a JSON error envelope such as {@code {"message":"Not Found"}} instead of a real
 *       404 status.</li>
 *   <li>Marketing/landing pages or WAFs sitting in front of the API that answer everything.</li>
 * </ul>
 *
 * <p>Against such a target, a path-guessing check reports one finding per path it guessed — e.g.
 * 21 CRITICAL "admin endpoint accessible" findings and 30 "debug endpoint exposed" findings for a
 * target that exposes none of them. The same inference in
 * {@link org.owasp.astf.core.discovery.EndpointDiscoveryService} fabricates endpoints that don't
 * exist, which then multiply the scan matrix (every phantom endpoint is re-tested by every test
 * case), inflating scan time and crowding out real coverage.</p>
 *
 * <h2>How it works</h2>
 *
 * <p>Before trusting any guessed path's 2xx, ask the target what an unknown path looks like:
 * request two deliberately-nonexistent paths (one at the root, one nested with a file extension,
 * since catch-alls are often scoped to one shape and not the other). Then:</p>
 *
 * <ul>
 *   <li>If both probes come back 4xx/5xx, the target distinguishes real paths from unknown ones.
 *       No catch-all exists, {@link #looksLikeUnknownPath} answers {@code false} for everything,
 *       and behaviour is identical to not using this class at all.</li>
 *   <li>If a probe comes back 2xx, that response is recorded as a sample of "what this target
 *       says about a path that isn't there". A later probe hit whose response is
 *       indistinguishable from that sample is the catch-all answering again, not a discovery.</li>
 * </ul>
 *
 * <p>Comparison is done on a normalised body (see {@link #normalizeBody}) so that a catch-all
 * page carrying a CSRF token, request id, hash or timestamp still matches itself across two
 * different URLs. Independently of any baseline, a 2xx response whose body is
 * an <em>error envelope</em> ({@code {"status":404}}, {@code {"message":"Not Found"}},
 * {@code Cannot GET /x}) is also treated as an unknown path, since no real endpoint reports its
 * own absence with a success status.</p>
 *
 * <h2>Bias</h2>
 *
 * <p>Matching is deliberately conservative — near-exact equality of the normalised body rather
 * than fuzzy similarity. Suppressing a genuine finding is a worse outcome for a security tool
 * than leaving a false positive in, so anything that isn't clearly the catch-all answering is
 * left alone and still reported.</p>
 *
 * <h2>Cost</h2>
 *
 * <p>Baselines are cached per base URL on the detector instance. Test cases hold one detector for
 * their lifetime and the registry creates each test case once per scan, so the probe costs two
 * requests per target per test case — not two per endpoint.</p>
 */
public class SoftNotFoundDetector {
    private static final Logger logger = LogManager.getLogger(SoftNotFoundDetector.class);

    /**
     * Upper bound on how much of a normalised body is retained per baseline sample. Catch-all
     * pages are small; this only bounds memory if a target streams something large back for an
     * unknown path, and comparison of the retained prefix is still decisive in practice.
     */
    private static final int MAX_RETAINED_BODY = 8192;

    /** Runs of 8+ hex/digit characters (request ids, CSRF tokens, hashes) are masked as volatile. */
    private static final Pattern VOLATILE_TOKEN = Pattern.compile("[0-9a-f]{8,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    /**
     * A numeric HTTP error status reported inside the body of an otherwise-2xx response, e.g.
     * {@code {"status": 404}} or {@code {"code":500}}. Quoted values are excluded on purpose so
     * that a health payload like {@code {"status":"UP"}} doesn't match.
     */
    private static final Pattern BODY_ERROR_STATUS =
            Pattern.compile("\"(?:status|statusCode|code)\"\\s*:\\s*[45]\\d{2}\\b", Pattern.CASE_INSENSITIVE);

    /**
     * A message field whose value states the resource doesn't exist. Restricted to "absence"
     * wording — a real endpoint can legitimately return a 200 body containing the word "error",
     * but not one announcing that the path it was reached at is unknown.
     */
    private static final Pattern BODY_NOT_FOUND_MESSAGE = Pattern.compile(
            "\"(?:error|message|detail|title|reason)\"\\s*:\\s*\"[^\"]{0,120}?"
                    + "(?:not\\s+found|no\\s+such|does\\s+not\\s+exist|unknown\\s+(?:route|path|endpoint|resource)"
                    + "|no\\s+route\\s+matched|resource\\s+missing)",
            Pattern.CASE_INSENSITIVE);

    /** Express/Connect and similar frameworks' default unknown-route body. */
    private static final Pattern CANNOT_METHOD_PATH = Pattern.compile(
            "cannot\\s+(?:get|post|put|patch|delete|head|options)\\s+/", Pattern.CASE_INSENSITIVE);

    private final Map<String, Baseline> baselinesByBaseUrl = new ConcurrentHashMap<>();

    /**
     * Reports whether {@code response} is indistinguishable from what {@code baseUrl} returns for
     * a path that doesn't exist, and therefore must not be read as evidence that the probed path
     * is real.
     *
     * <p>Answers {@code false} — i.e. "treat this response normally" — whenever the target has no
     * catch-all, whenever the response isn't a success, and whenever the baseline probe itself
     * couldn't be established. Callers can therefore add this check without changing behaviour
     * against any target that already answers 404 properly.</p>
     *
     * @param baseUrl    the target's base URL; {@code null}/blank disables the check
     * @param httpClient client used to establish the baseline on first call for this base URL
     * @param response   the response to a guessed path
     * @return {@code true} when the response is the target's generic unknown-path answer
     */
    public boolean looksLikeUnknownPath(String baseUrl, HttpClient httpClient, HttpResponse response) {
        if (response == null || !response.isSuccess()) {
            return false;
        }

        // A success status carrying a body that announces the resource is absent is a soft 404
        // on its own terms — no baseline needed, and true even on targets that 404 correctly
        // elsewhere.
        if (looksLikeNotFoundBody(response.getBody())) {
            return true;
        }

        if (baseUrl == null || baseUrl.isBlank() || httpClient == null) {
            return false;
        }

        Baseline baseline = baselineFor(baseUrl, httpClient);
        return baseline.matches(response);
    }

    /**
     * Reports whether the target serves a catch-all 2xx for unknown paths. Exposed so callers can
     * log or explain why results were suppressed; {@link #looksLikeUnknownPath} does not require
     * it to be consulted first.
     *
     * @param baseUrl    the target's base URL
     * @param httpClient client used to establish the baseline on first call for this base URL
     * @return {@code true} when at least one deliberately-nonexistent path returned 2xx
     */
    public boolean hasCatchAllResponses(String baseUrl, HttpClient httpClient) {
        if (baseUrl == null || baseUrl.isBlank() || httpClient == null) {
            return false;
        }
        return baselineFor(baseUrl, httpClient).catchAllPresent();
    }

    /**
     * Returns whether a response looks like a real API/service response rather than an HTML page.
     *
     * <p>SPAs and reverse proxies typically return HTTP 200 with {@code text/html} for every
     * unknown path (client-side routing fallback), which would otherwise produce false positives
     * for admin-path probing, method-escalation and deprecated-version checks. This is the shared
     * implementation of a check that was previously duplicated verbatim across test cases; its
     * behaviour is unchanged.</p>
     *
     * <p>A response is considered an API response when:</p>
     * <ul>
     *   <li>the {@code Content-Type} contains "json", "xml" or "text/plain", or</li>
     *   <li>the {@code Content-Type} is absent or unrecognised <em>and</em> the body starts with
     *       '{' or '[' (JSON).</li>
     * </ul>
     * A {@code text/html} content type always answers {@code false}.
     *
     * @param response the response to classify; {@code null} answers {@code false}
     * @return {@code true} when the response carries structured API data
     */
    public static boolean isApiResponse(HttpResponse response) {
        if (response == null) {
            return false;
        }

        String contentType = contentTypeOf(response);

        if (!contentType.isEmpty()) {
            // Explicit HTML -> SPA fallback, skip
            if (contentType.contains("text/html")) {
                return false;
            }
            // JSON, XML, plain text -> real API response
            if (contentType.contains("json") || contentType.contains("xml") || contentType.contains("text/plain")) {
                return true;
            }
        }

        // No Content-Type or unrecognised type - fall back to body sniffing
        String body = response.getBody();
        if (body != null) {
            String trimmed = body.stripLeading();
            return trimmed.startsWith("{") || trimmed.startsWith("[");
        }

        return false;
    }

    /**
     * Returns whether a response body states that the requested resource doesn't exist, which
     * makes an accompanying 2xx status a soft 404 regardless of what the rest of the target does.
     *
     * @param body the response body; {@code null}/blank answers {@code false}
     * @return {@code true} when the body is an absence/error envelope
     */
    public static boolean looksLikeNotFoundBody(String body) {
        if (body == null || body.isBlank()) {
            return false;
        }
        String sample = body.length() > MAX_RETAINED_BODY ? body.substring(0, MAX_RETAINED_BODY) : body;
        return BODY_ERROR_STATUS.matcher(sample).find()
                || BODY_NOT_FOUND_MESSAGE.matcher(sample).find()
                || CANNOT_METHOD_PATH.matcher(sample).find();
    }

    /**
     * Strips the parts of a body that legitimately vary between two requests for two different
     * unknown paths — request/trace ids, CSRF tokens, hashes, timestamps, counters — so that two
     * renderings of the same catch-all page compare equal.
     *
     * <p>Masking is intentionally broad: over-masking makes two genuinely different responses
     * more likely to compare equal, which only ever <em>suppresses</em> a probe hit, so the
     * comparison in {@link Baseline#matches} additionally requires the content-type family to
     * agree and the normalised lengths to stay within a small tolerance.</p>
     *
     * @param body raw response body; {@code null} normalises to an empty string
     * @return the normalised form used for baseline comparison
     */
    static String normalizeBody(String body) {
        if (body == null) {
            return "";
        }
        String sample = body.length() > MAX_RETAINED_BODY ? body.substring(0, MAX_RETAINED_BODY) : body;
        String normalized = sample.toLowerCase();
        normalized = VOLATILE_TOKEN.matcher(normalized).replaceAll("x");
        normalized = DIGITS.matcher(normalized).replaceAll("0");
        normalized = WHITESPACE.matcher(normalized).replaceAll(" ");
        return normalized.trim();
    }

    private Baseline baselineFor(String baseUrl, HttpClient httpClient) {
        Baseline cached = baselinesByBaseUrl.get(baseUrl);
        if (cached != null) {
            return cached;
        }

        // Probing outside the map's compute lock: a race just means two threads each send the
        // two probe requests and one of the results is discarded, which is cheaper than holding
        // a bin lock across network I/O.
        Baseline probed = probe(baseUrl, httpClient);
        Baseline existing = baselinesByBaseUrl.putIfAbsent(baseUrl, probed);
        return existing != null ? existing : probed;
    }

    private Baseline probe(String baseUrl, HttpClient httpClient) {
        String cleanBase = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        List<Sample> samples = new ArrayList<>(2);

        for (String probePath : probePaths()) {
            try {
                HttpResponse response = httpClient.getWithStatus(cleanBase + probePath, Map.of());
                if (response != null && response.isSuccess()) {
                    samples.add(new Sample(contentTypeFamily(response), normalizeBody(response.getBody())));
                }
            } catch (Exception e) {
                // A probe that can't be sent tells us nothing about the target's unknown-path
                // behaviour. Record no sample; the check then stays inert rather than guessing.
                logger.debug("Unknown-path baseline probe failed for {}{}: {}",
                        cleanBase, probePath, e.getMessage());
            }
        }

        if (!samples.isEmpty()) {
            logger.info("Target {} answers 2xx for deliberately-nonexistent paths — probe hits " +
                    "matching that generic response will not be reported as discoveries.", cleanBase);
        }
        return new Baseline(samples);
    }

    /**
     * Two shapes of unknown path, because a catch-all is often scoped to only one of them: a bare
     * root-level segment, and a nested path ending in a file extension (commonly excluded from
     * SPA rewrite rules, and commonly served by a static-file handler instead).
     */
    private static List<String> probePaths() {
        String token = Long.toHexString(ThreadLocalRandom.current().nextLong() & 0xFFFFFFFFFFFFL);
        return List.of(
                "/astf-unknown-path-probe-" + token,
                "/astf-unknown-path-probe-" + token + "/nested-" + token + ".json");
    }

    private static String contentTypeOf(HttpResponse response) {
        Map<String, List<String>> headers = response.getHeaders();
        if (headers == null) {
            return "";
        }
        return headers.entrySet().stream()
                .filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("Content-Type"))
                .flatMap(e -> e.getValue() != null ? e.getValue().stream() : java.util.stream.Stream.<String>empty())
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .orElse("")
                .toLowerCase();
    }

    /**
     * Collapses a Content-Type to the family that matters here, so that a charset parameter or a
     * vendor suffix doesn't stop a catch-all from matching itself.
     */
    private static String contentTypeFamily(HttpResponse response) {
        String contentType = contentTypeOf(response);
        if (contentType.contains("html")) return "html";
        if (contentType.contains("json")) return "json";
        if (contentType.contains("xml")) return "xml";
        if (contentType.contains("text/plain")) return "text";
        if (contentType.isEmpty()) return "";
        int separator = contentType.indexOf(';');
        return separator > 0 ? contentType.substring(0, separator).trim() : contentType.trim();
    }

    /** What one deliberately-nonexistent path returned. */
    private record Sample(String contentTypeFamily, String normalizedBody) {
    }

    /** What every deliberately-nonexistent path on one target returned. */
    private record Baseline(List<Sample> samples) {

        boolean catchAllPresent() {
            return !samples.isEmpty();
        }

        boolean matches(HttpResponse response) {
            if (samples.isEmpty()) {
                return false;
            }
            String family = contentTypeFamily(response);
            String normalized = normalizeBody(response.getBody());
            for (Sample sample : samples) {
                if (!sample.contentTypeFamily().equals(family)) {
                    continue;
                }
                if (sample.normalizedBody().equals(normalized) || nearlyIdentical(sample.normalizedBody(), normalized)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Equality of the normalised body already covers most catch-alls. This additionally
         * tolerates a small residue of variation that normalisation didn't mask — a rotating
         * nonce with punctuation in it, a slightly different wording of the same generic page —
         * by requiring the two bodies to be within 2% of each other in length and to agree on
         * 95% of their characters, counting from both ends.
         *
         * <p>Both ends are measured because the variation is typically in the middle of an
         * otherwise identical page; a leading-prefix-only comparison would score an 86-character
         * shell that differs in three characters at position 63 as only 73% similar.</p>
         */
        private static boolean nearlyIdentical(String left, String right) {
            if (left.isEmpty() || right.isEmpty()) {
                return left.equals(right);
            }
            int longest = Math.max(left.length(), right.length());
            int shortest = Math.min(left.length(), right.length());
            if (longest - shortest > Math.max(8, longest / 50)) {
                return false;
            }

            int prefix = 0;
            while (prefix < shortest && left.charAt(prefix) == right.charAt(prefix)) {
                prefix++;
            }

            // Bounded by the remaining characters so prefix and suffix can never count the same
            // character twice on strings that share a repeated run.
            int suffix = 0;
            int suffixLimit = shortest - prefix;
            while (suffix < suffixLimit
                    && left.charAt(left.length() - 1 - suffix) == right.charAt(right.length() - 1 - suffix)) {
                suffix++;
            }

            return prefix + suffix >= (int) (shortest * 0.95);
        }
    }
}
