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
            "(?i)([?&;](?:[a-z0-9_.-]*(?:token|secret|password|passwd|session|sig|auth|jwt|key)[a-z0-9_.-]*|code)=)([^&#]*)");

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

    /** Masks every value in a Cookie request header, keeping the names. */
    public static String maskCookie(String header) {
        if (header == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String part : header.split(";", -1)) {
            if (!first) {
                sb.append(';');
            }
            first = false;
            int eq = part.indexOf('=');
            sb.append(eq < 0 ? part : part.substring(0, eq + 1) + MARKER);
        }
        return sb.toString();
    }

    /** Masks the values of token-like query parameters in a Location header. */
    public static String maskLocation(String location) {
        if (location == null) {
            return null;
        }
        Matcher m = TOKEN_PARAM.matcher(location);
        return m.replaceAll(r -> Matcher.quoteReplacement(r.group(1) + MARKER));
    }
}
