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

    @ParameterizedTest(name = "{0} is an auth path to the word matcher")
    @ValueSource(strings = {
            // 2.0.2 matched these by substring; acronym runs, glued words and "authn"/"authorize"
            // must not lose them.
            "/api/v1/authn", "/api/authtoken", "/api/reauth", "/api/v1/authorize", "/api/authorization",
            "/api/APIToken", "/api/gettoken", "/api/refreshtoken", "/api/idtoken", "/api/authorize",
            "/api/oauth2token", "/api/AuthToken", "/api/IDToken"
    })
    void reviewerAuthPaths(String path) {
        assertTrue(PathKeywordMatcher.isAuthPath(path), path);
    }

    @ParameterizedTest(name = "{0} is a 2FA path to the word matcher")
    @ValueSource(strings = {
            "/api/OTPVerify", "/api/MFAChallenge", "/api/TOTPSetup", "/api/sendotp", "/api/verifyotp",
            "/api/2faVerify", "/api/mfa2"
    })
    void reviewerTwoFactorPaths(String path) {
        assertTrue(PathKeywordMatcher.isTwoFactorPath(path), path);
    }

    @ParameterizedTest(name = "{0} gets the login/2FA checks")
    @ValueSource(strings = {
            "/api/v1/authn", "/api/authtoken", "/api/reauth", "/api/v1/authorize", "/api/authorization",
            "/api/OTPVerify", "/api/MFAChallenge", "/api/TOTPSetup", "/api/APIToken", "/api/gettoken",
            "/api/refreshtoken", "/api/idtoken", "/api/sendotp", "/api/verifyotp", "/api/authorize"
    })
    void reviewerPathsGetLoginOr2faChecks(String path) {
        PathKeywordMatcher.Classification c = PathKeywordMatcher.classify(path);
        assertTrue(c.runAuthChecks() || c.runTwoFactorChecks(), path);
    }

    @ParameterizedTest(name = "{0}: generic checks and the 2.0.2 login/2FA checks both run")
    @ValueSource(strings = {"/api/tokens", "/api/authors", "/api/authorities", "/api/authorization-rules"})
    void substringOnlyAuthPathsGetBoth(String path) {
        PathKeywordMatcher.Classification c = PathKeywordMatcher.classify(path);
        assertTrue(c.ambiguous(), path);
        assertTrue(c.runGenericChecks(), path + " must keep the missing-auth/JWT checks");
        assertTrue(c.runAuthChecks(), path + " got the login checks in 2.0.2 and must keep them");
    }

    @ParameterizedTest(name = "{0}: generic checks and the 2.0.2 2FA checks both run")
    @ValueSource(strings = {"/api/discount-codes", "/api/otpauth-free-paths", "/api/barcodes"})
    void substringOnly2faPathsGetBoth(String path) {
        PathKeywordMatcher.Classification c = PathKeywordMatcher.classify(path);
        assertTrue(c.ambiguous(), path);
        assertTrue(c.runGenericChecks(), path);
        assertTrue(c.runTwoFactorChecks(), path + " got the 2FA checks in 2.0.2 and must keep them");
    }

    @ParameterizedTest(name = "{0}: new-only auth path also keeps the 2.0.2 generic checks")
    @ValueSource(strings = {"/api/logon", "/api/jwt", "/sso/saml", "/users/signon"})
    void newOnlyAuthPathsGetBoth(String path) {
        PathKeywordMatcher.Classification c = PathKeywordMatcher.classify(path);
        assertTrue(c.ambiguous(), path);
        assertTrue(c.runAuthChecks(), path);
        assertTrue(c.runGenericChecks(), path + " got the generic checks in 2.0.2 and must keep them");
    }

    @Test
    @DisplayName("Paths both classifiers agree on are not ambiguous")
    void agreementIsNotAmbiguous() {
        PathKeywordMatcher.Classification login = PathKeywordMatcher.classify("/api/v1/auth/login");
        assertFalse(login.ambiguous());
        assertTrue(login.runAuthChecks());
        assertFalse(login.runGenericChecks());

        PathKeywordMatcher.Classification users = PathKeywordMatcher.classify("/api/users");
        assertFalse(users.ambiguous());
        assertFalse(users.runAuthChecks());
        assertFalse(users.runTwoFactorChecks());
        assertTrue(users.runGenericChecks());
    }

    @Test
    @DisplayName("The 2.0.2 substring lists are reproduced exactly")
    void legacySubstringClassification() {
        assertTrue(PathKeywordMatcher.legacyIsAuthPath("/api/AUTHORS"));
        assertTrue(PathKeywordMatcher.legacyIsAuthPath("/api/tokens"));
        assertFalse(PathKeywordMatcher.legacyIsAuthPath("/api/logon"));
        assertTrue(PathKeywordMatcher.legacyIsTwoFactorPath("/api/discount-codes"));
        assertTrue(PathKeywordMatcher.legacyIsSqlAuthLikePath("/api/authors"));
        assertFalse(PathKeywordMatcher.legacyIsSqlAuthLikePath("/api/token"),
                "the 2.0.2 NoSQL list had no token keyword");
    }

    @Test
    @DisplayName("Matching is case-insensitive and keyword lists are honoured")
    void customKeywords() {
        assertTrue(PathKeywordMatcher.matchesAny("/Api/LogIn", List.of("login")));
        assertFalse(PathKeywordMatcher.matchesAny("/api/x", List.of()));
        assertFalse(PathKeywordMatcher.matchesAny(null, List.of("login")));
    }
}
