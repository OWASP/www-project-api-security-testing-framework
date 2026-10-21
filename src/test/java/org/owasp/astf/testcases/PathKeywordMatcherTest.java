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
            "/api/login?next=/home",
            // Login paths whose keyword is part of a longer word; substring matching in 2.0.2
            // caught these and whole-word matching alone does not.
            "/api/authenticate", "/api/authentication", "/oauth2/authorize", "/api/userlogin",
            "/users/signon", "/api/logon", "/sessions", "/api/v1/sessions", "/api/accesstoken",
            "/api/JWTAuth", "/sso/saml", "/api/token", "/api/accessToken", "/api/v2/Authenticate",
            "/api/user-sign-in", "/api/log-in", "/api/sign-on", "/api/ssoCallback", "/api/saml2/acs",
            "/api/jwt", "/api/sessionid", "/api/usersession", "/api/OAuthCallback",
            // A plural or suffixed strong stem still counts, the same as in 2.0.2.
            "/api/sessions-report", "/api/logins-history"
    })
    void authPaths(String path) {
        assertTrue(PathKeywordMatcher.isAuthPath(path), path);
    }

    @ParameterizedTest(name = "{0} is NOT an auth path")
    @ValueSource(strings = {
            "/api/tokens", "/api/authors", "/api/authorization-rules", "/api/authorities",
            "/api/authority", "/api/discount-codes", "/api/otpauth-free-paths", "/api/blogin",
            "/api/bloginfo", "/api/catalog-index", "/api/users/{token}", "/api/users/:session",
            "/api/items?redirect=/login", "/api/lessons", "/api/processors", "/api/professors",
            "/api/associates", "/api/possessions", "/api/obsessions", "/api/designing",
            "/", ""
    })
    void notAuthPaths(String path) {
        assertFalse(PathKeywordMatcher.isAuthPath(path), path);
    }

    @ParameterizedTest(name = "{0} is a 2FA path")
    @ValueSource(strings = {
            "/api/2fa/verify", "/api/2FA", "/api/mfa", "/identity/api/auth/v2/check-otp", "/api/verifyOtp",
            "/api/two-factor", "/api/two_factor/setup", "/api/twoFactor", "/api/totp", "/api/otp",
            "/api/enable2fa", "/api/user/2fa-setup", "/api/verify", "/api/mfa/challenge"
    })
    void twoFactorPaths(String path) {
        assertTrue(PathKeywordMatcher.isTwoFactorPath(path), path);
    }

    @ParameterizedTest(name = "{0} is NOT a 2FA path")
    @ValueSource(strings = {
            "/api/discount-codes", "/api/otpauth-free-paths", "/api/barcodes", "/api/codecs",
            "/api/remfa", "/api/factor", "/api/two", "/api/tokens", "/api/authors"
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
