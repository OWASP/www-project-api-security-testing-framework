package org.owasp.astf.testcases;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PathKeywordMatcher: whole-segment path classification")
class PathKeywordMatcherTest {

    @ParameterizedTest(name = "{0} is an auth path")
    @ValueSource(strings = {
            "/api/v1/auth/login", "/login", "/LOGIN", "/users/v1/login", "/api/sign-in", "/api/signIn",
            "/api/signin", "/oauth/token", "/api/session", "/identity/api/auth/signup", "/api/auth-v2/x",
            "/api/login?next=/home"
    })
    void authPaths(String path) {
        assertTrue(PathKeywordMatcher.isAuthPath(path), path);
    }

    @ParameterizedTest(name = "{0} is NOT an auth path")
    @ValueSource(strings = {
            "/api/tokens", "/api/authors", "/api/authorization-rules", "/api/sessions-report",
            "/api/logins-history", "/api/blogin", "/api/users/{token}", "/api/users/:session",
            "/api/items?redirect=/login", "/", ""
    })
    void notAuthPaths(String path) {
        assertFalse(PathKeywordMatcher.isAuthPath(path), path);
    }

    @ParameterizedTest(name = "{0} is a 2FA path")
    @ValueSource(strings = {
            "/api/2fa/verify", "/api/2FA", "/api/mfa", "/identity/api/auth/v2/check-otp", "/api/verifyOtp",
            "/api/two-factor", "/api/two_factor/setup", "/api/twoFactor", "/api/totp", "/api/otp"
    })
    void twoFactorPaths(String path) {
        assertTrue(PathKeywordMatcher.isTwoFactorPath(path), path);
    }

    @ParameterizedTest(name = "{0} is NOT a 2FA path")
    @ValueSource(strings = {
            "/api/discount-codes", "/api/otpauth-free-paths", "/api/barcodes", "/api/codecs",
            "/api/remfa", "/api/factor", "/api/two"
    })
    void notTwoFactorPaths(String path) {
        assertFalse(PathKeywordMatcher.isTwoFactorPath(path), path);
    }

    @Test
    @DisplayName("Matching is case-insensitive and keyword lists are honoured")
    void customKeywords() {
        assertTrue(PathKeywordMatcher.matchesAny("/Api/LogIn", List.of("login")));
        assertFalse(PathKeywordMatcher.matchesAny("/api/x", List.of()));
        assertFalse(PathKeywordMatcher.matchesAny(null, List.of("login")));
    }
}
