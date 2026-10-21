package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.function.Predicate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;

/**
 * Probe helper for checks whose finding says "without authorization" or "publicly accessible".
 * The probe is first sent with no credentials at all. Only if that is not accepted, and the scan
 * has credentials of its own, is it sent again with them, so a resource that needs the scan's
 * credentials is still reported, but as reachable with the configured credentials rather than as
 * public.
 */
final class AnonymousFirstProbe {
    private static final Logger logger = LogManager.getLogger(AnonymousFirstProbe.class);

    /** Title suffix for a finding that was only shown with the scan's own credentials. */
    static final String CREDENTIALED_SUFFIX = " (reachable with the configured credentials)";

    @FunctionalInterface
    interface Send {
        HttpResponse send() throws IOException;
    }

    /**
     * @param response  the response to report on, or {@code null} if nothing was received
     * @param anonymous true if {@code response} came from the request sent without credentials
     */
    record Result(HttpResponse response, boolean anonymous) { }

    private AnonymousFirstProbe() { }

    /**
     * Sends {@code anonymous}; returns its response if {@code accepted} holds. Otherwise, when
     * the client has credentials configured, sends {@code credentialed} and returns that response
     * (accepted or not). If the credentialed request fails, the anonymous response is returned.
     *
     * @throws IOException only when no response at all could be obtained
     */
    static Result probe(HttpClient httpClient, Send anonymous, Send credentialed,
                        Predicate<HttpResponse> accepted) throws IOException {
        HttpResponse anonymousResponse = null;
        IOException anonymousError = null;
        try {
            anonymousResponse = anonymous.send();
        } catch (IOException e) {
            anonymousError = e;
        }
        if (anonymousResponse != null && accepted.test(anonymousResponse)) {
            return new Result(anonymousResponse, true);
        }
        if (httpClient.hasConfiguredCredentials()) {
            try {
                HttpResponse credentialedResponse = credentialed.send();
                if (credentialedResponse != null) {
                    return new Result(credentialedResponse, false);
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
        return new Result(anonymousResponse, true);
    }
}
