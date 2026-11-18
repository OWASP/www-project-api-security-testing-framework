package org.owasp.astf.core.result;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal masking of header values that are copied into finding evidence, so reports do not
 * carry live session cookies or tokens.
 */
public final class EvidenceMasking {

    public static final String MARKER = "[REDACTED]";

    private static final Pattern TOKEN_PARAM = Pattern.compile(
            "(?i)([?&;#](?:[a-z0-9_.-]*(?:token|secret|password|passwd|pwd|pass|session|sig|auth|jwt|key|ticket|saml|assertion|credential)[a-z0-9_.-]*|code)=)([^&#]*)");

    // user:password@ in the authority part of a URL
    private static final Pattern USER_INFO = Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@?#]*@");

    private EvidenceMasking() {
    }

    /** Masks the cookie value of a Set-Cookie header, keeping the name and the attributes. */
    public static String maskSetCookie(String header) {
        if (header == null) {
            return null;
        }
        int semi = header.indexOf(';');
        String pair = semi >= 0 ? header.substring(0, semi) : header;
        String rest = semi >= 0 ? header.substring(semi) : "";
        int eq = pair.indexOf('=');
        if (eq < 0) {
            return header;
        }
        return pair.substring(0, eq + 1) + MARKER + rest;
    }

    /** Masks the values of token-like query or fragment parameters in a Location header (e.g. ?token=x, #access_token=x). */
    public static String maskLocation(String location) {
        if (location == null) {
            return null;
        }
        String withoutUserInfo = USER_INFO.matcher(location).replaceFirst("$1" + Matcher.quoteReplacement(MARKER) + "@");
        Matcher m = TOKEN_PARAM.matcher(withoutUserInfo);
        return m.replaceAll(r -> Matcher.quoteReplacement(r.group(1) + MARKER));
    }
}
