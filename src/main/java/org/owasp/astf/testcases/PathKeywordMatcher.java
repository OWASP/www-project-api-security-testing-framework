package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Classifies a request path as a login/authentication endpoint or a 2FA endpoint.
 *
 * <p>Each literal path segment is split into words on {@code -}, {@code _}, {@code .} and
 * camelCase boundaries and compared case-insensitively. Path parameter placeholders
 * ({@code {token}}, {@code :token}) and the query string are ignored. Two kinds of keyword are
 * used:</p>
 *
 * <ul>
 *   <li><b>Strong stems</b> ({@link #AUTH_STEMS}, {@link #TWO_FACTOR_STEMS}) almost never occur in
 *       an ordinary resource name, so they match anywhere inside a word: {@code /api/authenticate},
 *       {@code /api/userlogin}, {@code /oauth2/authorize}, {@code /api/v1/sessions},
 *       {@code /api/JWTAuth}, {@code /api/enable2fa}. A few English words that contain a stem
 *       are listed in {@link #STEM_EXCEPTIONS} ({@code /api/lessons}, {@code /api/processors},
 *       {@code /api/possessions}, {@code /api/bloginfo}, {@code /api/catalog-index}), and
 *       "sso" only counts at the start of a word because it occurs inside many common words.</li>
 *   <li><b>Weak keywords</b> ({@link #AUTH_KEYWORDS}, {@link #TWO_FACTOR_KEYWORDS}) are short or
 *       common enough to appear inside resource names, so they must be a whole word (or, for a
 *       compound such as "sign-in", a contiguous run of words). "token" matches {@code /oauth/token}
 *       and {@code /api/accessToken} but not the resource collection {@code /api/tokens}; "auth"
 *       matches {@code /auth} and {@code /auth-v2} but not {@code /api/authors},
 *       {@code /api/authority} or {@code /api/authorization-rules}; "otp" does not match
 *       {@code /api/otpauth-free-paths}; "code" does not match {@code /api/discount-codes}.</li>
 * </ul>
 */
public final class PathKeywordMatcher {

    /** Stems that identify a login / authentication / session endpoint wherever they appear in a word. */
    public static final List<String> AUTH_STEMS = List.of(
            "login", "logon", "signin", "signon", "authenticat", "oauth", "sso", "saml", "jwt",
            "accesstoken", "session"
    );

    /** Keywords that identify a login / authentication endpoint only as a whole word. */
    public static final List<String> AUTH_KEYWORDS = List.of(
            "auth", "token", "sign-in", "sign-on", "log-in", "log-on"
    );

    /** Stems that identify a 2FA endpoint wherever they appear in a word. */
    public static final List<String> TWO_FACTOR_STEMS = List.of("2fa");

    /** Keywords that identify a 2FA / MFA / OTP endpoint only as a whole word. */
    public static final List<String> TWO_FACTOR_KEYWORDS = List.of(
            "mfa", "otp", "totp", "2fa", "two-factor", "multifactor", "multi-factor", "verify", "code"
    );

    /**
     * Ordinary words that contain a strong stem. A word containing one of these is not counted
     * for that stem (it can still match through another keyword).
     */
    static final Map<String, List<String>> STEM_EXCEPTIONS = Map.of(
            "login", List.of("blogin", "cataloging", "catalogin"),
            "session", List.of("possession", "obsession"),
            "signin", List.of("designin", "resignin", "assignin", "consignin"),
            "signon", List.of("consignon")
    );

    /** Stems that only count at the start of a word, because they occur inside common words. */
    private static final List<String> WORD_START_STEMS = List.of("sso");

    private PathKeywordMatcher() {
    }

    /** True when the path names an authentication endpoint (strong stem in a word, or weak keyword as a word). */
    public static boolean isAuthPath(String path) {
        return matchesStem(path, AUTH_STEMS) || matchesAny(path, AUTH_KEYWORDS);
    }

    /** True when the path names a 2FA/MFA/OTP endpoint (strong stem in a word, or weak keyword as a word). */
    public static boolean isTwoFactorPath(String path) {
        return matchesStem(path, TWO_FACTOR_STEMS) || matchesAny(path, TWO_FACTOR_KEYWORDS);
    }

    /**
     * True when any keyword matches a whole word (or contiguous run of words, for compound
     * keywords) inside one literal segment of the path.
     */
    public static boolean matchesAny(String path, Collection<String> keywords) {
        for (List<String> words : segmentWords(path)) {
            for (String keyword : keywords) {
                if (containsRun(words, words(keyword))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** True when any stem occurs inside a word of one literal segment of the path. */
    public static boolean matchesStem(String path, Collection<String> stems) {
        for (List<String> words : segmentWords(path)) {
            for (String word : words) {
                for (String stem : stems) {
                    if (wordHasStem(word, stem)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean wordHasStem(String word, String stem) {
        boolean found = WORD_START_STEMS.contains(stem) ? word.startsWith(stem) : word.contains(stem);
        if (!found) {
            return false;
        }
        for (String exception : STEM_EXCEPTIONS.getOrDefault(stem, List.of())) {
            if (word.contains(exception)) {
                return false;
            }
        }
        return true;
    }

    private static List<List<String>> segmentWords(String path) {
        List<List<String>> out = new ArrayList<>();
        if (path == null || path.isEmpty()) {
            return out;
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
            if (!words.isEmpty()) {
                out.add(words);
            }
        }
        return out;
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
