package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Classifies a request path by whole path segments rather than by substring.
 *
 * <p>Substring matching misclassifies ordinary resources: {@code /api/tokens} contains "token",
 * {@code /api/authors} contains "auth", {@code /api/discount-codes} contains "code". When such a
 * path is taken for a login or 2FA endpoint, the generic missing-auth and JWT checks never run on
 * it. Here a keyword matches only when it is a whole word of a path segment.</p>
 *
 * <p>Each literal segment is split into words on {@code -}, {@code _}, {@code .} and camelCase
 * boundaries, compared case-insensitively. A keyword matches when its own words appear as a
 * contiguous run in the segment's words, so "auth" matches {@code /auth} and {@code /auth-v2},
 * "otp" matches {@code /check-otp} and {@code /verifyOtp}, and the compound "two-factor"
 * matches {@code /two-factor}, {@code /two_factor} and {@code /twoFactor}. "token" does not match
 * {@code /tokens} and "otp" does not match {@code /otpauth-free-paths}. Path parameter
 * placeholders ({@code {token}}, {@code :token}) and the query string are ignored.</p>
 */
public final class PathKeywordMatcher {

    /** Keywords that identify a login / authentication / session endpoint. */
    public static final List<String> AUTH_KEYWORDS = List.of(
            "login", "auth", "token", "signin", "sign-in", "oauth", "session"
    );

    /** Keywords that identify a 2FA / MFA / OTP endpoint. */
    public static final List<String> TWO_FACTOR_KEYWORDS = List.of(
            "mfa", "otp", "totp", "2fa", "two-factor", "multifactor", "multi-factor", "verify", "code"
    );

    private PathKeywordMatcher() {
    }

    /** True when the path names an authentication endpoint by a whole segment word. */
    public static boolean isAuthPath(String path) {
        return matchesAny(path, AUTH_KEYWORDS);
    }

    /** True when the path names a 2FA/MFA/OTP endpoint by a whole segment word. */
    public static boolean isTwoFactorPath(String path) {
        return matchesAny(path, TWO_FACTOR_KEYWORDS);
    }

    /**
     * True when any keyword matches a whole word (or contiguous run of words, for compound
     * keywords) inside one literal segment of the path.
     */
    public static boolean matchesAny(String path, Collection<String> keywords) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        String withoutQuery = path;
        int q = withoutQuery.indexOf('?');
        if (q >= 0) {
            withoutQuery = withoutQuery.substring(0, q);
        }
        int h = withoutQuery.indexOf('#');
        if (h >= 0) {
            withoutQuery = withoutQuery.substring(0, h);
        }
        for (String segment : withoutQuery.split("/")) {
            if (segment.isEmpty() || segment.startsWith("{") || segment.startsWith(":")) {
                continue;
            }
            List<String> words = words(segment);
            for (String keyword : keywords) {
                if (containsRun(words, words(keyword))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<String> words(String text) {
        String split = text.replaceAll("(?<=[a-z])(?=[A-Z])", "-");
        List<String> out = new ArrayList<>();
        for (String w : split.toLowerCase(Locale.ROOT).split("[-_.]+")) {
            if (!w.isEmpty()) {
                out.add(w);
            }
        }
        return out;
    }

    private static boolean containsRun(List<String> words, List<String> run) {
        if (run.isEmpty() || words.isEmpty()) {
            return false;
        }
        // The whole segment spelled with different separators or casing ("LogIn", "log-in"
        // for "login").
        if (String.join("", words).equals(String.join("", run))) {
            return true;
        }
        if (run.size() > words.size()) {
            return false;
        }
        for (int i = 0; i + run.size() <= words.size(); i++) {
            if (words.subList(i, i + run.size()).equals(run)) {
                return true;
            }
        }
        // A compound keyword written as one word in the path ("twofactor" for "two-factor").
        if (run.size() > 1) {
            String joined = String.join("", run);
            return words.contains(joined);
        }
        return false;
    }
}
