package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.function.Predicate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;

/**
 * Probe helper for checks whose finding says "without authorization" or "publicly accessible".
 * The probe is first sent with no credentials at all. Only if that is not accepted is it sent
 * again exactly as 2.0.2 sent it (the normal request, with the scan's configured credentials,
 * custom headers and cookies), so a resource that 2.0.2 reported is still reported, but as
 * reachable with the configured credentials (or headers, or cookies) rather than as public.
 */
final class AnonymousFirstProbe {
    private static final Logger logger = LogManager.getLogger(AnonymousFirstProbe.class);

    /** Title suffix for a finding that was only shown with the scan's own credentials. */
    static final String CREDENTIALED_SUFFIX = " (reachable with the configured credentials)";

    /**
     * Title suffix for a finding only shown with the scan's configured custom headers, when the
     * scan has no identity credential (token, API key, Basic Auth, Authorization or Cookie header).
     */
    static final String CONFIGURED_HEADERS_SUFFIX = " (reachable with the configured headers)";

    /**
     * Title suffix for a finding only shown with cookies the target set during a scan that was
     * configured with no credentials or custom headers at all.
     */
    static final String SCAN_COOKIES_SUFFIX = " (reachable with cookies set during the scan)";

    @FunctionalInterface
    interface Send {
        HttpResponse send() throws IOException;
    }

    /** What the reported response was sent with. */
    enum Mode {
        ANONYMOUS("", "without credentials"),
        CREDENTIALS(CREDENTIALED_SUFFIX, "with the configured credentials"),
        CONFIGURED_HEADERS(CONFIGURED_HEADERS_SUFFIX, "with the configured headers"),
        SCAN_COOKIES(SCAN_COOKIES_SUFFIX, "with cookies the target set during the scan");

        private final String suffix;
        private final String sentWith;

        Mode(String suffix, String sentWith) {
            this.suffix = suffix;
            this.sentWith = sentWith;
        }
    }

    /**
     * @param response the response to report on, or {@code null} if nothing was received
     * @param mode     how {@code response} was sent
     */
    record Result(HttpResponse response, Mode mode) {
        /** @return true if {@code response} came from the request sent without credentials */
        boolean anonymous() {
            return mode == Mode.ANONYMOUS;
        }

        /** @return the title suffix for a finding on {@code response} ("" when anonymous) */
        String suffix() {
            return mode.suffix;
        }

        /** @return how the request was sent, e.g. "with the configured headers", for evidence */
        String sentWith() {
            return mode.sentWith;
        }
    }

    private AnonymousFirstProbe() { }

    /**
     * Sends {@code anonymous}; returns its response if {@code accepted} holds. Otherwise, when
     * the 2.0.2 request ({@code credentialed}) would differ from the anonymous one (the scan has
     * configured credentials or custom headers, or the target set a cookie for {@code url} during
     * the scan), sends {@code credentialed} and returns that response (accepted or not). If the
     * credentialed request fails, the anonymous response is returned.
     *
     * @param url the URL both requests go to, used to see whether a scan cookie would ride along
     * @throws IOException only when no response at all could be obtained
     */
    static Result probe(HttpClient httpClient, String url, Send anonymous, Send credentialed,
                        Predicate<HttpResponse> accepted) throws IOException {
        HttpResponse anonymousResponse = null;
        IOException anonymousError = null;
        try {
            anonymousResponse = anonymous.send();
        } catch (IOException e) {
            anonymousError = e;
        }
        if (anonymousResponse != null && accepted.test(anonymousResponse)) {
            return new Result(anonymousResponse, Mode.ANONYMOUS);
        }
        Mode retryMode = retryMode(httpClient, url);
        if (retryMode != null) {
            try {
                HttpResponse credentialedResponse = credentialed.send();
                if (credentialedResponse != null) {
                    return new Result(credentialedResponse, retryMode);
                }
            } catch (IOException e) {
                logger.debug("Credentialed retry failed: {}", e.getMessage());
                if (anonymousResponse == null) {
                    throw e;
                }
            }
        }
        if (anonymousResponse == null && anonymousError != null) {
            throw anonymousError;
        }
        return new Result(anonymousResponse, Mode.ANONYMOUS);
    }

    /**
     * @return how a retry sent as 2.0.2 sent it differs from the anonymous request, or
     *     {@code null} if it would be the same request
     */
    static Mode retryMode(HttpClient httpClient, String url) {
        if (httpClient.hasIdentityCredentials()) {
            return Mode.CREDENTIALS;
        }
        if (httpClient.hasConfiguredCredentials()) {
            return Mode.CONFIGURED_HEADERS;
        }
        if (httpClient.hasCookiesFor(url)) {
            return Mode.SCAN_COOKIES;
        }
        return null;
    }
}
