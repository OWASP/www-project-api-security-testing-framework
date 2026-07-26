package org.owasp.astf.testcases;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Tests for API2:2023 Broken Authentication.
 *
 * <p>Covers weak credentials, JWT algorithm attacks (none / expired tokens),
 * session-cookie security flags, and 2FA/MFA bypass attempts.</p>
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API2:2023</a>
 */
public class BrokenAuthenticationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(BrokenAuthenticationTestCase.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final List<String> AUTH_PATH_PATTERNS = List.of(
            "login", "auth", "token", "signin", "oauth", "session"
    );

    private static final List<String> TWO_FA_PATH_PATTERNS = List.of(
            "mfa", "otp", "totp", "2fa", "two-factor", "multifactor", "verify", "code"
    );

    // JWT with "none" algorithm - known attack payload
    private static final String NONE_ALG_JWT =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +  // {"alg":"none","typ":"JWT"}
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ" + // {"sub":"1234567890","name":"Admin","iat":1516239022}
            ".";  // empty signature

    // JWT with "none" algorithm and an already-expired exp claim (2001-09-08)
    private static final String EXPIRED_JWT =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" +  // {"alg":"none","typ":"JWT"}
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiZXhwIjoxMDAwMDAwMDAwfQ" + // {"sub":"...","name":"Admin","exp":1000000000}
            ".";  // empty signature

    // Commonly-guessed OTP codes used in 2FA bypass attempts
    private static final List<String> WEAK_OTP_CODES = List.of(
            "000000", "123456", "111111", "999999", "654321", "112233"
    );

    // Some APIs return HTTP 200 on both success AND failure, carrying the real result only in
    // the response body (e.g. VAmPI: {"status":"fail","message":"..."} with a 200 status).
    // A 2xx status code alone is therefore not sufficient evidence of a successful auth bypass —
    // it must also be checked against these common failure markers in the body.
    // Common account names tried for the enumeration check — a heuristic, not exhaustive: this
    // reliably detects the vulnerability class on any target using one of these very common
    // account names, but (like any wordlist-based technique) can't prove its absence.
    private static final List<String> COMMON_USERNAMES = List.of("admin", "test", "user", "root", "guest");

    // Phrases distinguishing an "unknown account" response from a "wrong password for a real
    // account" response — the differential signal user-enumeration checks look for.
    private static final List<String> NO_SUCH_USER_MARKERS = List.of(
            "no such user", "user not found", "username not found", "account not found",
            "user does not exist", "unknown user", "no account", "user doesn't exist"
    );

    private static final int BRUTE_FORCE_ATTEMPTS = 8;

    private static final List<String> AUTH_FAILURE_BODY_MARKERS = List.of(
            "\"status\":\"fail\"", "\"status\": \"fail\"",
            "\"success\":false", "\"success\": false",
            "\"authenticated\":false", "\"authenticated\": false",
            "incorrect", "invalid credentials", "invalid username", "invalid password",
            "authentication failed", "login failed", "unauthorized", "access denied",
            "wrong password", "not correct", "does not match"
    );

    @Override
    public String getId() {
        return "ASTF-API2-2023";
    }

    @Override
    public String getName() {
        return "Broken Authentication";
    }

    @Override
    public String getDescription() {
        return """
               Tests for authentication weaknesses such as weak passwords, improper \
               token validation, missing or inconsistent authentication checks, \
               insecure session cookies, 2FA bypass, and credential exposure in URLs.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        // Always check for credential leakage in URLs (applies to all endpoint types)
        findings.addAll(checkTokenInUrl(endpoint));

        boolean isAuth  = isAuthEndpoint(endpoint);
        boolean is2FA   = is2FAEndpoint(endpoint);

        // Session-cookie checks apply to auth and 2FA endpoints (they set cookies on success)
        if (isAuth || is2FA) {
            findings.addAll(testSessionCookieSecurity(endpoint, httpClient));
        }

        if (isAuth) {
            findings.addAll(testWeakAuthentication(endpoint, httpClient));
            findings.addAll(testUserEnumeration(endpoint, httpClient));
            findings.addAll(testBruteForceLockout(endpoint, httpClient));
            findings.addAll(testTwoFactorBypass(endpoint, httpClient));
        } else if (is2FA) {
            findings.addAll(testTwoFactorBypass(endpoint, httpClient));
        } else {
            findings.addAll(testMissingAuthentication(endpoint, httpClient));
            findings.addAll(testJwtNoneAlgorithm(endpoint, httpClient));
            findings.addAll(testJwtAnalysis(endpoint, httpClient));
        }

        return findings;
    }

    private boolean isAuthEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return AUTH_PATH_PATTERNS.stream().anyMatch(path::contains);
    }

    private boolean is2FAEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return TWO_FA_PATH_PATTERNS.stream().anyMatch(path::contains);
    }

    /**
     * A 2xx status code alone does not prove an authentication attempt succeeded — some APIs
     * (e.g. VAmPI) return HTTP 200 for both successful and failed logins, with the real outcome
     * only in the response body. This checks the status code AND scans the body for common
     * failure markers before treating the response as a genuine success.
     */
    private boolean looksLikeAuthSuccess(HttpResponse response) {
        if (response == null || !response.isSuccess()) {
            return false;
        }
        String body = response.getBody();
        if (body == null || body.isBlank()) {
            return true; // no body to contradict the status code
        }
        String lower = body.toLowerCase();
        return AUTH_FAILURE_BODY_MARKERS.stream().noneMatch(lower::contains);
    }

    private List<Finding> testWeakAuthentication(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        // Common weak credentials to test
        List<Map<String, String>> weakCredentials = List.of(
                Map.of("username", "admin", "password", "admin"),
                Map.of("username", "admin", "password", "password"),
                Map.of("username", "admin", "password", "admin123"),
                Map.of("username", "test", "password", "test"),
                Map.of("username", "user", "password", "password")
        );

        String fullUrl = endpoint.getFullUrl();
        for (Map<String, String> creds : weakCredentials) {
            try {
                String body = String.format("{\"username\":\"%s\",\"password\":\"%s\"}",
                        creds.get("username"), creds.get("password"));
                HttpResponse response = httpClient.postWithStatus(fullUrl, Map.of(), "application/json", body);

                if (looksLikeAuthSuccess(response)) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Weak Default Credentials Accepted",
                            String.format("The authentication endpoint accepted weak credentials: %s/%s",
                                    creds.get("username"), creds.get("password")),
                            Severity.CRITICAL,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Enforce strong password policies, remove default credentials, and implement account lockout after failed attempts."
                    );
                    finding.setRequestDetails("POST " + fullUrl + " with credentials: " + creds.get("username"));
                    finding.setResponseDetails("Status: " + response.getStatusCode());
                    findings.add(finding);
                    break; // One finding is enough
                }
            } catch (Exception e) {
                logger.debug("Error testing weak credentials on {}: {}", endpoint, e.getMessage());
            }
        }

        // Check for missing account lockout (no rate limiting or lockout after multiple attempts)
        if (findings.isEmpty()) {
            findings.add(new Finding(
                    UUID.randomUUID().toString(),
                    "Authentication Endpoint Requires Manual Review",
                    "Authentication endpoints should be carefully reviewed for weak credentials, " +
                    "account lockout mechanisms, rate limiting, and proper token validation.",
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Implement strong password policies, account lockout after failed attempts, " +
                    "rate limiting, and proper token generation using industry-standard algorithms."
            ));
        }

        return findings;
    }

    /**
     * Tests for username enumeration: compares the login response for a definitely-nonexistent,
     * randomly-generated username against a set of very common account names ({@link
     * #COMMON_USERNAMES}), both with the same wrong password. A meaningfully different response
     * (different status code, or a body that mentions "no such user" for one but not the other)
     * indicates the API distinguishes "unknown account" from "wrong password for a real account,"
     * letting an attacker enumerate valid usernames before brute-forcing them.
     * <p>
     * This is a heuristic, not an exhaustive check: it can only detect the vulnerability if one
     * of the common names happens to be a real account. A negative result doesn't prove the
     * target is safe, only that none of these particular names revealed a difference — the same
     * limitation any wordlist-based technique has.
     */
    List<Finding> testUserEnumeration(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        String fullUrl = endpoint.getFullUrl();
        String randomUsername = "nonexistent_" + UUID.randomUUID().toString().substring(0, 8);

        try {
            HttpResponse randomResponse = httpClient.postWithStatus(fullUrl, Map.of(), "application/json",
                    String.format("{\"username\":\"%s\",\"password\":\"WrongPass!23\"}", randomUsername));
            if (randomResponse == null) {
                return findings;
            }

            for (String commonUsername : COMMON_USERNAMES) {
                HttpResponse commonResponse = httpClient.postWithStatus(fullUrl, Map.of(), "application/json",
                        String.format("{\"username\":\"%s\",\"password\":\"WrongPass!23\"}", commonUsername));
                if (commonResponse == null) {
                    continue;
                }

                if (responsesRevealEnumeration(randomResponse, commonResponse)) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "User Enumeration via Differential Login Response",
                            String.format("The login endpoint responds differently to a definitely-nonexistent " +
                                    "username ('%s') than to the common account name '%s', both with an " +
                                    "incorrect password. This lets an attacker enumerate valid usernames " +
                                    "before attempting to brute-force their passwords.",
                                    randomUsername, commonUsername),
                            Severity.MEDIUM,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Return an identical, generic response (same status code and message, e.g. " +
                            "\"Invalid username or password\") regardless of whether the account exists."
                    );
                    finding.setEvidence(String.format(
                            "Random username '%s' -> HTTP %d%nCommon username '%s' -> HTTP %d",
                            randomUsername, randomResponse.getStatusCode(),
                            commonUsername, commonResponse.getStatusCode()));
                    findings.add(finding);
                    return findings; // one confirmed instance is enough
                }
            }
        } catch (Exception e) {
            logger.debug("Error testing user enumeration on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private boolean responsesRevealEnumeration(HttpResponse a, HttpResponse b) {
        if (a.getStatusCode() != b.getStatusCode()) {
            return true;
        }
        String bodyA = a.getBody() != null ? a.getBody().toLowerCase() : "";
        String bodyB = b.getBody() != null ? b.getBody().toLowerCase() : "";
        boolean aSaysNoSuchUser = NO_SUCH_USER_MARKERS.stream().anyMatch(bodyA::contains);
        boolean bSaysNoSuchUser = NO_SUCH_USER_MARKERS.stream().anyMatch(bodyB::contains);
        return aSaysNoSuchUser != bSaysNoSuchUser;
    }

    /**
     * Tests for missing account lockout / rate limiting: sends {@link #BRUTE_FORCE_ATTEMPTS}
     * consecutive failed login attempts against the same (common) account and confirms the API
     * never responds with a rate-limit or lockout signal (HTTP 429, or 423 Locked). No lockout
     * after repeated failures means credential-stuffing and brute-force attacks face no
     * automated resistance.
     */
    List<Finding> testBruteForceLockout(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        String fullUrl = endpoint.getFullUrl();
        HttpResponse lastResponse = null;

        try {
            for (int attempt = 0; attempt < BRUTE_FORCE_ATTEMPTS; attempt++) {
                lastResponse = httpClient.postWithStatus(fullUrl, Map.of(), "application/json",
                        String.format("{\"username\":\"admin\",\"password\":\"WrongPass-%d!\"}", attempt));
                if (lastResponse == null) {
                    return findings;
                }
                if (lastResponse.isRateLimited() || lastResponse.getStatusCode() == 423) {
                    return findings; // lockout/rate-limiting is working correctly
                }
            }

            Finding finding = new Finding(
                    UUID.randomUUID().toString(),
                    "No Account Lockout or Rate Limiting on Repeated Failed Logins",
                    String.format("%d consecutive failed login attempts against the same account produced " +
                            "no rate-limiting or lockout response (HTTP 429/423). This allows unrestricted " +
                            "brute-force and credential-stuffing attacks against user accounts.",
                            BRUTE_FORCE_ATTEMPTS),
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getMethod() + " " + endpoint.getPath(),
                    "Implement account lockout or exponential rate limiting after a small number of failed " +
                    "attempts (e.g. 5), and consider CAPTCHA or IP-based throttling for repeated failures."
            );
            finding.setEvidence("Last of " + BRUTE_FORCE_ATTEMPTS + " attempts returned HTTP " +
                    lastResponse.getStatusCode() + " with no lockout signal");
            findings.add(finding);
        } catch (Exception e) {
            logger.debug("Error testing brute-force lockout on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private List<Finding> testMissingAuthentication(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.isRequiresAuthentication()) {
            return findings;
        }

        try {
            String fullUrl = endpoint.getFullUrl();
            HttpResponse response = null;

            // Send request without any authentication headers
            Map<String, String> noAuthHeaders = Map.of();
            switch (endpoint.getMethod().toUpperCase()) {
                case "GET"    -> response = httpClient.getWithStatus(fullUrl, noAuthHeaders);
                case "POST"   -> response = httpClient.postWithStatus(fullUrl, noAuthHeaders, "application/json", "{}");
                case "PUT"    -> response = httpClient.putWithStatus(fullUrl, noAuthHeaders, "application/json", "{}");
                case "DELETE" -> response = httpClient.deleteWithStatus(fullUrl, noAuthHeaders);
                default -> {
                    // Fall back to string-based check for unsupported methods
                    String body = httpClient.get(fullUrl, noAuthHeaders);
                    if (body != null && !body.isEmpty()
                            && !body.contains("unauthorized")
                            && !body.contains("authentication")) {
                        findings.add(buildMissingAuthFinding(endpoint));
                    }
                    return findings;
                }
            }

            if (looksLikeAuthSuccess(response)) {
                // A 2xx response without auth headers indicates missing authentication controls
                findings.add(buildMissingAuthFinding(endpoint));
            }
        } catch (Exception e) {
            logger.debug("Error testing missing authentication on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private Finding buildMissingAuthFinding(EndpointInfo endpoint) {
        return new Finding(
                UUID.randomUUID().toString(),
                "Missing Authentication Controls",
                "The API endpoint appears to be accessible without proper authentication.",
                Severity.HIGH,
                getId(),
                endpoint.getMethod() + " " + endpoint.getPath(),
                "Implement consistent authentication checks across all API endpoints that require them."
        );
    }

    private List<Finding> testJwtNoneAlgorithm(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.isRequiresAuthentication()) {
            return findings;
        }

        try {
            String fullUrl = endpoint.getFullUrl();

            // Step 1 — baseline probe: send the request with NO auth header.
            // If the server returns 2xx without any credentials the endpoint is public;
            // a subsequent 2xx with a JWT-none token tells us nothing (it would have
            // returned 2xx anyway).  Only proceed when the baseline is 4xx/5xx.
            HttpResponse baseline = switch (endpoint.getMethod().toUpperCase()) {
                case "POST"   -> httpClient.postWithStatus(fullUrl, Map.of(), "application/json", "{}");
                case "PUT"    -> httpClient.putWithStatus(fullUrl, Map.of(), "application/json", "{}");
                case "DELETE" -> httpClient.deleteWithStatus(fullUrl, Map.of());
                default       -> httpClient.getWithStatus(fullUrl, Map.of());
            };

            if (baseline == null || baseline.isSuccess()) {
                // Endpoint is publicly accessible — JWT-none test would be a false positive.
                logger.debug("Skipping JWT-none test for {} {} — endpoint is publicly accessible (baseline HTTP {})",
                        endpoint.getMethod(), endpoint.getPath(),
                        baseline == null ? "null" : baseline.getStatusCode());
                return findings;
            }

            // Step 2 — send the JWT-none token.  A 2xx response NOW means the unsigned
            // token bypassed authentication on an endpoint that normally requires it.
            Map<String, String> noneAlgHeaders = Map.of("Authorization", "Bearer " + NONE_ALG_JWT);
            HttpResponse response = switch (endpoint.getMethod().toUpperCase()) {
                case "POST"   -> httpClient.postWithStatus(fullUrl, noneAlgHeaders, "application/json", "{}");
                case "PUT"    -> httpClient.putWithStatus(fullUrl, noneAlgHeaders, "application/json", "{}");
                case "DELETE" -> httpClient.deleteWithStatus(fullUrl, noneAlgHeaders);
                default       -> httpClient.getWithStatus(fullUrl, noneAlgHeaders);
            };

            if (looksLikeAuthSuccess(response)) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "JWT 'none' Algorithm Accepted",
                        "The API accepted a JWT token with 'none' signing algorithm, which means " +
                        "tokens can be forged without a valid signature.",
                        Severity.CRITICAL,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Always validate JWT signatures. Reject tokens with 'none' or 'null' algorithm. " +
                        "Use a whitelist of accepted signing algorithms."
                );
                finding.setEvidence("Server returned HTTP " + response.getStatusCode() +
                        " when presented with a JWT using 'none' algorithm (baseline without auth: HTTP " +
                        baseline.getStatusCode() + ")");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing JWT none algorithm on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    private List<Finding> checkTokenInUrl(EndpointInfo endpoint) {
        List<Finding> findings = new ArrayList<>();
        String path = endpoint.getPath().toLowerCase();

        // Check if the URL path contains patterns suggesting token/credential leakage
        List<String> tokenPatterns = List.of("token=", "api_key=", "apikey=", "access_token=",
                "auth=", "password=", "secret=");

        for (String pattern : tokenPatterns) {
            if (path.contains(pattern)) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Sensitive Token Exposed in URL",
                        "Authentication token or credentials appear to be passed in the URL, " +
                        "which can be captured in server logs, browser history, and proxy caches.",
                        Severity.HIGH,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Pass authentication tokens in the Authorization header or request body, never in URLs."
                );
                finding.setEvidence("Pattern '" + pattern + "' found in endpoint path: " + endpoint.getPath());
                findings.add(finding);
                break;
            }
        }

        return findings;
    }

    /**
     * Tests JWT handling beyond the "none" algorithm: specifically checks whether the server
     * accepts tokens with an expired {@code exp} claim.  A server that does so is not
     * validating token expiry, allowing reuse of old/stolen tokens.
     *
     * @param endpoint   the endpoint under test
     * @param httpClient the HTTP client
     * @return list of findings (may be empty)
     */
    List<Finding> testJwtAnalysis(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.isRequiresAuthentication()) {
            return findings;
        }

        findings.addAll(testExpiredJwt(endpoint, httpClient));
        findings.addAll(testJwtKidPathTraversal(endpoint, httpClient));
        findings.addAll(testJwtAlgorithmConfusion(endpoint, httpClient));
        findings.addAll(testJwtJkuProcessing(endpoint, httpClient));
        return findings;
    }

    /**
     * Sends a request authenticated with an already-expired JWT (exp = 1 000 000 000,
     * i.e. September 2001).  A 2xx response reveals the server does not validate
     * the expiry claim.
     */
    private List<Finding> testExpiredJwt(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        try {
            String fullUrl = endpoint.getFullUrl();

            // Step 1 — baseline probe with no auth.  If the endpoint is public (returns 2xx
            // without credentials) an expired-JWT "bypass" is meaningless — skip it.
            HttpResponse baseline = switch (endpoint.getMethod().toUpperCase()) {
                case "POST"   -> httpClient.postWithStatus(fullUrl, Map.of(), "application/json", "{}");
                case "PUT"    -> httpClient.putWithStatus(fullUrl, Map.of(), "application/json", "{}");
                case "DELETE" -> httpClient.deleteWithStatus(fullUrl, Map.of());
                default       -> httpClient.getWithStatus(fullUrl, Map.of());
            };

            if (baseline == null || baseline.isSuccess()) {
                logger.debug("Skipping expired-JWT test for {} {} — endpoint is publicly accessible (baseline HTTP {})",
                        endpoint.getMethod(), endpoint.getPath(),
                        baseline == null ? "null" : baseline.getStatusCode());
                return findings;
            }

            // Step 2 — send expired JWT only when the baseline required auth.
            Map<String, String> expiredJwtHeaders = Map.of("Authorization", "Bearer " + EXPIRED_JWT);

            HttpResponse response = switch (endpoint.getMethod().toUpperCase()) {
                case "POST"   -> httpClient.postWithStatus(fullUrl, expiredJwtHeaders, "application/json", "{}");
                case "PUT"    -> httpClient.putWithStatus(fullUrl, expiredJwtHeaders, "application/json", "{}");
                case "DELETE" -> httpClient.deleteWithStatus(fullUrl, expiredJwtHeaders);
                default       -> httpClient.getWithStatus(fullUrl, expiredJwtHeaders);
            };

            if (looksLikeAuthSuccess(response)) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "Expired JWT Token Accepted",
                        "The API accepted a JWT token whose expiry claim (exp) has long since passed. " +
                        "This allows attackers to reuse stolen tokens indefinitely.",
                        Severity.HIGH,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Validate the 'exp' claim on every request. Reject tokens whose expiry has passed " +
                        "and use short-lived tokens (e.g. 15-60 minutes) with refresh-token rotation."
                );
                finding.setEvidence("Server returned HTTP " + response.getStatusCode() +
                        " when presented with a JWT whose exp=1000000000 (September 2001)" +
                        " (baseline without auth: HTTP " + baseline.getStatusCode() + ")");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing expired JWT on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    /**
     * Tests the classic "kid: /dev/null" JWT attack: some servers use the {@code kid} (Key ID)
     * header to look up a key file on disk (e.g. {@code keys/<kid>.pem}) without sanitizing it.
     * A path-traversal {@code kid} pointing at {@code /dev/null} makes the server "find" an empty
     * key file — reading zero bytes as the HMAC secret — so a token signed with an empty-string
     * HS256 secret is accepted as validly signed.
     */
    List<Finding> testJwtKidPathTraversal(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            String fullUrl = endpoint.getFullUrl();

            HttpResponse baseline = probeWithoutAuth(endpoint, httpClient, fullUrl);
            if (baseline == null || baseline.isSuccess()) {
                return findings; // publicly accessible — a forged-token "bypass" would be meaningless
            }

            String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../../../../../../../../../dev/null\"}";
            String payload = "{\"sub\":\"admin\",\"role\":\"admin\",\"iat\":" + (System.currentTimeMillis() / 1000) + "}";
            String forgedJwt = signHs256(header, payload, new byte[0]);

            Map<String, String> headers = Map.of("Authorization", "Bearer " + forgedJwt);
            HttpResponse response = switch (endpoint.getMethod().toUpperCase()) {
                case "POST"   -> httpClient.postWithStatus(fullUrl, headers, "application/json", "{}");
                case "PUT"    -> httpClient.putWithStatus(fullUrl, headers, "application/json", "{}");
                case "DELETE" -> httpClient.deleteWithStatus(fullUrl, headers);
                default       -> httpClient.getWithStatus(fullUrl, headers);
            };

            if (looksLikeAuthSuccess(response)) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "JWT 'kid' Path Traversal Accepted",
                        "The API accepted a JWT whose 'kid' (Key ID) header was a path-traversal string " +
                        "pointing at /dev/null, signed with HS256 using an empty secret (simulating the " +
                        "server reading an empty file as the verification key). This means the 'kid' " +
                        "header's value is used to locate a key file on disk without validation.",
                        Severity.CRITICAL,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Never derive a filesystem path or key lookup directly from a client-supplied JWT " +
                        "header. Use a fixed allowlist of known key IDs, and reject any 'kid' value that " +
                        "isn't an exact match."
                );
                finding.setEvidence("Server returned HTTP " + response.getStatusCode() +
                        " for a token with kid='../../../../../../../../../../dev/null' signed with an empty HMAC secret " +
                        "(baseline without auth: HTTP " + baseline.getStatusCode() + ")");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing JWT kid path traversal on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    /**
     * Tests RS256-to-HS256 algorithm confusion: if the server exposes its RSA public key (via a
     * JWKS endpoint) and doesn't strictly enforce the expected signing algorithm, an attacker can
     * sign a token with HS256 using the server's own PUBLIC key bytes as the HMAC secret. Because
     * the server already has that exact public key on hand to "verify" the signature, and HMAC
     * verification is just "does re-computing the HMAC with our key match" — it does — the forged
     * token passes. Requires the target to actually expose a JWKS; skipped entirely otherwise
     * since there's no key material to build a forged token from.
     */
    List<Finding> testJwtAlgorithmConfusion(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            byte[] publicKeyBytes = fetchRsaPublicKeyBytes(endpoint, httpClient);
            if (publicKeyBytes == null) {
                return findings; // no exposed JWKS — nothing to build a forged token from
            }

            String fullUrl = endpoint.getFullUrl();
            HttpResponse baseline = probeWithoutAuth(endpoint, httpClient, fullUrl);
            if (baseline == null || baseline.isSuccess()) {
                return findings;
            }

            String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            String payload = "{\"sub\":\"admin\",\"role\":\"admin\",\"iat\":" + (System.currentTimeMillis() / 1000) + "}";
            String forgedJwt = signHs256(header, payload, publicKeyBytes);

            Map<String, String> headers = Map.of("Authorization", "Bearer " + forgedJwt);
            HttpResponse response = switch (endpoint.getMethod().toUpperCase()) {
                case "POST"   -> httpClient.postWithStatus(fullUrl, headers, "application/json", "{}");
                case "PUT"    -> httpClient.putWithStatus(fullUrl, headers, "application/json", "{}");
                case "DELETE" -> httpClient.deleteWithStatus(fullUrl, headers);
                default       -> httpClient.getWithStatus(fullUrl, headers);
            };

            if (looksLikeAuthSuccess(response)) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "JWT Algorithm Confusion (RS256 to HS256) Accepted",
                        "The API accepted a JWT signed with HS256 using its own published RSA public key " +
                        "(from the exposed JWKS) as the HMAC secret. This is the classic RS256-to-HS256 " +
                        "algorithm-confusion attack: since the server already has that exact public key, " +
                        "it can 'verify' an HMAC signature computed with it, letting anyone forge tokens " +
                        "without ever knowing the server's private key.",
                        Severity.CRITICAL,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Enforce a strict allowlist of accepted signing algorithms per key/endpoint — never " +
                        "trust the 'alg' header from the token itself. Use a JWT library configured to " +
                        "reject algorithm mismatches (e.g. expecting RS256 but receiving HS256)."
                );
                finding.setEvidence("Server returned HTTP " + response.getStatusCode() +
                        " for an HS256 token signed with the server's own RSA public key bytes as the secret " +
                        "(baseline without auth: HTTP " + baseline.getStatusCode() + ")");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing JWT algorithm confusion on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    /**
     * Detects (does not exploit) processing of the JWT {@code jku} (JWK Set URL) header — a
     * header telling the verifier where to fetch the signing key from. If the server fetches
     * whatever URL an attacker supplies without an allowlist, that's both an SSRF vector and a
     * signature-forgery vector (point {@code jku} at attacker-hosted keys, sign with the matching
     * private key). Fully exploiting it requires hosting attacker-controlled key material at a
     * reachable URL, which this framework has no ability to do from a black-box scan — so this
     * only detects whether the header is processed at all (via a response-latency signal, the
     * same approach {@link RegexDosTestCase} uses), and flags it as INFO for manual follow-up
     * rather than claiming forgery.
     */
    List<Finding> testJwtJkuProcessing(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();
        try {
            String fullUrl = endpoint.getFullUrl();

            long baselineStart = System.currentTimeMillis();
            HttpResponse baseline = probeWithoutAuth(endpoint, httpClient, fullUrl);
            long baselineElapsed = System.currentTimeMillis() - baselineStart;
            if (baseline == null || baseline.isSuccess()) {
                return findings;
            }

            String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"," +
                    "\"jku\":\"http://169.254.169.254.astf-jku-probe.invalid/jwks.json\"}";
            String payload = "{\"sub\":\"admin\",\"iat\":" + (System.currentTimeMillis() / 1000) + "}";
            String probeJwt = signHs256(header, payload, new byte[]{0});

            long start = System.currentTimeMillis();
            boolean timedOut = false;
            HttpResponse response = null;
            try {
                Map<String, String> headers = Map.of("Authorization", "Bearer " + probeJwt);
                response = switch (endpoint.getMethod().toUpperCase()) {
                    case "POST"   -> httpClient.postWithStatus(fullUrl, headers, "application/json", "{}");
                    case "PUT"    -> httpClient.putWithStatus(fullUrl, headers, "application/json", "{}");
                    case "DELETE" -> httpClient.deleteWithStatus(fullUrl, headers);
                    default       -> httpClient.getWithStatus(fullUrl, headers);
                };
            } catch (IOException e) {
                timedOut = true;
            }
            long elapsed = System.currentTimeMillis() - start;

            boolean tookMuchLonger = elapsed > Math.max(3000, baselineElapsed * 8);
            String responseBody = response != null ? response.getBody() : null;
            boolean errorMentionsUrl = responseBody != null &&
                    responseBody.toLowerCase().contains("astf-jku-probe.invalid");

            if (timedOut || tookMuchLonger || errorMentionsUrl) {
                Finding finding = new Finding(
                        UUID.randomUUID().toString(),
                        "JWT 'jku' Header Processed — Manual SSRF/Forgery Review Recommended",
                        "The server appears to process the JWT 'jku' (JWK Set URL) header — an attempt to " +
                        "fetch a key set from an attacker-controlled URL caused a " +
                        (timedOut ? "connection timeout" : errorMentionsUrl ? "response mentioning the probe URL"
                                : "significant response delay") +
                        ". If 'jku' isn't restricted to an allowlist of trusted hosts, this is both an SSRF " +
                        "vector and a signature-forgery vector (an attacker can host their own signing key " +
                        "at a URL they control). This framework can't fully exploit this without hosting " +
                        "attacker-controlled key material — manual verification is recommended.",
                        Severity.INFO,
                        getId(),
                        endpoint.getMethod() + " " + endpoint.getPath(),
                        "Never fetch keys from a client-supplied URL. Use a fixed, server-side key store, " +
                        "or if 'jku' must be supported, strictly validate it against an allowlist of trusted " +
                        "hosts before fetching."
                );
                finding.setEvidence(timedOut
                        ? "Request with jku header timed out (baseline: " + baselineElapsed + "ms)"
                        : "Response took " + elapsed + "ms with jku header set (baseline: " + baselineElapsed + "ms)");
                findings.add(finding);
            }
        } catch (Exception e) {
            logger.debug("Error testing JWT jku processing on {}: {}", endpoint, e.getMessage());
        }
        return findings;
    }

    /** Sends a request with no auth header, used as the "endpoint actually requires auth" baseline. */
    private HttpResponse probeWithoutAuth(EndpointInfo endpoint, HttpClient httpClient, String fullUrl) throws IOException {
        return switch (endpoint.getMethod().toUpperCase()) {
            case "POST"   -> httpClient.postWithStatus(fullUrl, Map.of(), "application/json", "{}");
            case "PUT"    -> httpClient.putWithStatus(fullUrl, Map.of(), "application/json", "{}");
            case "DELETE" -> httpClient.deleteWithStatus(fullUrl, Map.of());
            default       -> httpClient.getWithStatus(fullUrl, Map.of());
        };
    }

    /** Signs {@code header}.{@code payload} with HS256, producing a complete, valid-shaped JWT. */
    private String signHs256(String headerJson, String payloadJson, byte[] secret) throws Exception {
        String headerB64 = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;

        Mac mac = Mac.getInstance("HmacSHA256");
        // HmacSHA256 requires a non-empty key — a genuinely empty secret (the /dev/null case) is
        // represented as a single zero byte, which produces the same practical effect for this
        // test's purposes (a fixed, attacker-known "secret") without tripping InvalidKeyException.
        byte[] keyBytes = secret.length == 0 ? new byte[]{0} : secret;
        mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
        byte[] signature = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));

        return signingInput + "." + base64UrlEncode(signature);
    }

    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    // Memoizes fetchRsaPublicKeyBytes per base URL, since the JWKS location is a property of the
    // target as a whole, not of any individual endpoint — without this, a scan with N endpoints
    // repeated the same (usually all-404) JWKS probe N times over, once per endpoint, needlessly
    // multiplying scan duration. A zero-length array is the "checked, nothing found" sentinel
    // (a real encoded RSA key is never empty), distinguishing "not yet checked" (absent from the
    // map) from "checked and no JWKS exists" (present, empty) in this thread-safe cache.
    private final Map<String, byte[]> jwksCache = new java.util.concurrent.ConcurrentHashMap<>();
    private static final byte[] JWKS_NOT_FOUND = new byte[0];

    /**
     * Attempts to fetch and parse an RSA public key from a JWKS endpoint at a few common paths.
     * Returns the key's X.509-encoded bytes (the classic algorithm-confusion technique's HMAC
     * secret material), or {@code null} if no JWKS is exposed or the first key isn't RSA.
     */
    private byte[] fetchRsaPublicKeyBytes(EndpointInfo endpoint, HttpClient httpClient) {
        String baseUrl = endpoint.getBaseUrl() != null ? endpoint.getBaseUrl() : "";
        byte[] cached = jwksCache.computeIfAbsent(baseUrl, url -> {
            byte[] result = fetchRsaPublicKeyBytesUncached(url, httpClient);
            return result != null ? result : JWKS_NOT_FOUND;
        });
        return cached == JWKS_NOT_FOUND ? null : cached;
    }

    private byte[] fetchRsaPublicKeyBytesUncached(String baseUrl, HttpClient httpClient) {
        List<String> jwksPaths = List.of("/.well-known/jwks.json", "/jwks.json", "/oauth/jwks", "/auth/jwks.json");

        for (String path : jwksPaths) {
            try {
                HttpResponse response = httpClient.getWithStatus(baseUrl + path, Map.of());
                if (response == null || !response.isSuccess() || response.getBody() == null) {
                    continue;
                }
                JsonNode root = objectMapper.readTree(response.getBody());
                JsonNode keys = root.path("keys");
                if (!keys.isArray() || keys.isEmpty()) {
                    continue;
                }
                JsonNode key = keys.get(0);
                String n = key.path("n").asText(null);
                String e = key.path("e").asText(null);
                if (n == null || e == null) {
                    continue;
                }

                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
                return publicKey.getEncoded();
            } catch (Exception ex) {
                logger.debug("No usable JWKS at {}: {}", path, ex.getMessage());
            }
        }
        return null;
    }

    /**
     * Checks that session cookies returned by an authentication or 2FA endpoint carry the
     * {@code HttpOnly}, {@code Secure}, and {@code SameSite} security attributes.  Missing
     * attributes expose users to XSS-based session hijacking and CSRF attacks.
     *
     * @param endpoint   the endpoint under test
     * @param httpClient the HTTP client
     * @return list of findings (may be empty)
     */
    List<Finding> testSessionCookieSecurity(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        try {
            String fullUrl = endpoint.getFullUrl();
            HttpResponse response;

            if (endpoint.getMethod().equalsIgnoreCase("POST")) {
                response = httpClient.postWithStatus(fullUrl, Map.of(), "application/json", "{}");
            } else {
                response = httpClient.getWithStatus(fullUrl, Map.of());
            }

            if (response == null) {
                return findings;
            }

            // Inspect every Set-Cookie header value
            List<String> setCookieHeaders = response.getHeaders().entrySet().stream()
                    .filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase("Set-Cookie"))
                    .flatMap(e -> e.getValue().stream())
                    .toList();

            for (String cookieHeader : setCookieHeaders) {
                String lower = cookieHeader.toLowerCase();
                List<String> missingFlags = new ArrayList<>();

                if (!lower.contains("httponly")) {
                    missingFlags.add("HttpOnly");
                }
                if (!lower.contains("secure")) {
                    missingFlags.add("Secure");
                }
                if (!lower.contains("samesite")) {
                    missingFlags.add("SameSite");
                }

                if (!missingFlags.isEmpty()) {
                    String flagList = String.join(", ", missingFlags);
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "Insecure Session Cookie — Missing Security Flags",
                            "A session cookie is missing the following security attribute(s): " + flagList + ". " +
                            "HttpOnly prevents XSS-based theft; Secure ensures the cookie is only sent over HTTPS; " +
                            "SameSite mitigates CSRF attacks.",
                            Severity.MEDIUM,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Set the HttpOnly, Secure, and SameSite=Strict (or Lax) attributes on all session cookies."
                    );
                    finding.setEvidence("Set-Cookie: " + cookieHeader +
                            " — missing flag(s): " + flagList);
                    findings.add(finding);
                }
            }
        } catch (Exception e) {
            logger.debug("Error testing session cookie security on {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    /**
     * Attempts to bypass 2FA/MFA by submitting commonly-guessed OTP codes.  A 2xx response
     * for any of the codes indicates inadequate OTP validation.
     *
     * @param endpoint   the endpoint under test (auth or 2FA path)
     * @param httpClient the HTTP client
     * @return list of findings (may be empty)
     */
    List<Finding> testTwoFactorBypass(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        String fullUrl = endpoint.getFullUrl();

        for (String code : WEAK_OTP_CODES) {
            try {
                String body = String.format("{\"code\":\"%s\"}", code);
                HttpResponse response = httpClient.postWithStatus(fullUrl, Map.of(), "application/json", body);

                if (looksLikeAuthSuccess(response)) {
                    Finding finding = new Finding(
                            UUID.randomUUID().toString(),
                            "2FA/MFA Bypass — Weak OTP Code Accepted",
                            String.format("The 2FA/MFA endpoint accepted the guessable OTP code '%s'. " +
                                    "This completely undermines multi-factor authentication.", code),
                            Severity.CRITICAL,
                            getId(),
                            endpoint.getMethod() + " " + endpoint.getPath(),
                            "Enforce cryptographically random OTP generation (TOTP/HOTP per RFC 6238/4226), " +
                            "implement brute-force lockout after 3-5 failed attempts, and ensure codes expire quickly."
                    );
                    finding.setEvidence("Server returned HTTP " + response.getStatusCode() +
                            " when OTP code '" + code + "' was submitted");
                    findings.add(finding);
                    break; // One finding is sufficient
                }
            } catch (Exception e) {
                logger.debug("Error testing 2FA bypass code {} on {}: {}", code, endpoint, e.getMessage());
            }
        }

        return findings;
    }
}
