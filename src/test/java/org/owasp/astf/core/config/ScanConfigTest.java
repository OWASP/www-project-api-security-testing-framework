package org.owasp.astf.core.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.EndpointInfo;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ScanConfig}.
 *
 * <p>Covers default values, mutators, edge-cases, and convenience
 * methods (issue #26).</p>
 */
@DisplayName("ScanConfig unit tests")
class ScanConfigTest {

    private ScanConfig config;

    @BeforeEach
    void setUp() {
        config = new ScanConfig();
    }

    // ── defaults ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Default: discoveryEnabled is true")
    void defaultDiscoveryEnabled() {
        assertTrue(config.isDiscoveryEnabled(),
                "Discovery should be enabled by default");
    }

    @Test
    @DisplayName("Default: threads is 10")
    void defaultThreads() {
        assertEquals(10, config.getThreads());
    }

    @Test
    @DisplayName("Default: timeoutMinutes is 30")
    void defaultTimeoutMinutes() {
        assertEquals(30, config.getTimeoutMinutes());
    }

    @Test
    @DisplayName("Default: requestDelayMs is 0")
    void defaultRequestDelayMs() {
        assertEquals(0, config.getRequestDelayMs());
    }

    @Test
    @DisplayName("Default: followRedirects is true")
    void defaultFollowRedirects() {
        assertTrue(config.isFollowRedirects());
    }

    @Test
    @DisplayName("Default: validateCertificates is true")
    void defaultValidateCertificates() {
        assertTrue(config.isValidateCertificates());
    }

    @Test
    @DisplayName("Default: outputFormat is JSON")
    void defaultOutputFormat() {
        assertEquals(ScanConfig.OutputFormat.JSON, config.getOutputFormat());
    }

    @Test
    @DisplayName("Default: collections are empty (not null)")
    void defaultCollectionsAreEmpty() {
        assertNotNull(config.getHeaders());
        assertTrue(config.getHeaders().isEmpty());

        assertNotNull(config.getEndpoints());
        assertTrue(config.getEndpoints().isEmpty());

        assertNotNull(config.getEnabledTestCaseIds());
        assertTrue(config.getEnabledTestCaseIds().isEmpty());

        assertNotNull(config.getDisabledTestCaseIds());
        assertTrue(config.getDisabledTestCaseIds().isEmpty());

        assertNotNull(config.getExcludePatterns());
        assertTrue(config.getExcludePatterns().isEmpty());

        assertNotNull(config.getExcludeSeverities());
        assertTrue(config.getExcludeSeverities().isEmpty());
    }

    // ── setTargetUrl — trailing-slash behaviour ──────────────────────────────

    @Test
    @DisplayName("setTargetUrl appends trailing slash when missing")
    void setTargetUrlAppendsSlash() {
        config.setTargetUrl("https://api.example.com");
        assertEquals("https://api.example.com/", config.getTargetUrl());
    }

    @Test
    @DisplayName("setTargetUrl keeps existing trailing slash")
    void setTargetUrlKeepsExistingSlash() {
        config.setTargetUrl("https://api.example.com/");
        assertEquals("https://api.example.com/", config.getTargetUrl());
    }

    @Test
    @DisplayName("setTargetUrl accepts null without throwing")
    void setTargetUrlNull() {
        assertDoesNotThrow(() -> config.setTargetUrl(null));
        assertNull(config.getTargetUrl());
    }

    // ── setBearerToken — auto Authorization header ───────────────────────────

    @Test
    @DisplayName("setBearerToken automatically adds Authorization header")
    void setBearerTokenAddsAuthHeader() {
        config.setBearerToken("my-token-abc");

        assertTrue(config.getHeaders().containsKey("Authorization"),
                "Authorization header should be added automatically");
        assertEquals("Bearer my-token-abc", config.getHeaders().get("Authorization"));
    }

    @Test
    @DisplayName("setBearerToken does NOT overwrite existing Authorization header")
    void setBearerTokenDoesNotOverwriteExisting() {
        config.addHeader("Authorization", "Bearer existing-token");
        config.setBearerToken("new-token");

        // The existing header should be preserved
        assertEquals("Bearer existing-token", config.getHeaders().get("Authorization"),
                "Existing Authorization header must not be overwritten");
    }

    @Test
    @DisplayName("setBearerToken with null does not add Authorization header")
    void setBearerTokenNullDoesNotAddHeader() {
        config.setBearerToken(null);
        assertFalse(config.getHeaders().containsKey("Authorization"));
    }

    @Test
    @DisplayName("setBearerToken with empty string does not add Authorization header")
    void setBearerTokenEmptyDoesNotAddHeader() {
        config.setBearerToken("");
        assertFalse(config.getHeaders().containsKey("Authorization"));
    }

    // ── addHeader ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("addHeader stores the header and it is retrievable")
    void addHeader() {
        config.addHeader("X-Custom-Header", "custom-value");
        assertEquals("custom-value", config.getHeaders().get("X-Custom-Header"));
    }

    @Test
    @DisplayName("addHeader: later value overwrites earlier for same key")
    void addHeaderOverwrites() {
        config.addHeader("X-Api-Key", "first");
        config.addHeader("X-Api-Key", "second");
        assertEquals("second", config.getHeaders().get("X-Api-Key"));
    }

    // ── addEndpoint ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("addEndpoint appends to the endpoints list")
    void addEndpoint() {
        EndpointInfo ep = new EndpointInfo("/api/v1/users", "GET");
        config.addEndpoint(ep);

        assertEquals(1, config.getEndpoints().size());
        assertSame(ep, config.getEndpoints().get(0));
    }

    @Test
    @DisplayName("setEndpoints replaces the entire list")
    void setEndpoints() {
        config.addEndpoint(new EndpointInfo("/old", "GET"));
        List<EndpointInfo> newList = List.of(
                new EndpointInfo("/new1", "GET"),
                new EndpointInfo("/new2", "POST")
        );
        config.setEndpoints(newList);

        assertEquals(2, config.getEndpoints().size());
    }

    // ── OutputFormat enum ────────────────────────────────────────────────────

    @Test
    @DisplayName("OutputFormat enum contains JSON, XML, HTML, SARIF")
    void outputFormatValues() {
        ScanConfig.OutputFormat[] formats = ScanConfig.OutputFormat.values();
        assertEquals(4, formats.length);

        assertNotNull(ScanConfig.OutputFormat.valueOf("JSON"));
        assertNotNull(ScanConfig.OutputFormat.valueOf("XML"));
        assertNotNull(ScanConfig.OutputFormat.valueOf("HTML"));
        assertNotNull(ScanConfig.OutputFormat.valueOf("SARIF"));
    }

    // ── proxy settings ───────────────────────────────────────────────────────

    @Test
    @DisplayName("Proxy host and port round-trip correctly")
    void proxySettings() {
        config.setProxyHost("proxy.example.com");
        config.setProxyPort(8080);
        config.setProxyUsername("user");
        config.setProxyPassword("pass");

        assertEquals("proxy.example.com", config.getProxyHost());
        assertEquals(8080, config.getProxyPort());
        assertEquals("user", config.getProxyUsername());
        assertEquals("pass", config.getProxyPassword());
    }

    // ── API key settings ─────────────────────────────────────────────────────

    @Test
    @DisplayName("API key and custom header name are stored correctly")
    void apiKeySettings() {
        config.setApiKey("my-api-key");
        config.setApiKeyHeader("X-API-KEY");

        assertEquals("my-api-key", config.getApiKey());
        assertEquals("X-API-KEY", config.getApiKeyHeader());
    }

    @Test
    @DisplayName("Default API key header name is X-API-Key")
    void defaultApiKeyHeader() {
        assertEquals("X-API-Key", config.getApiKeyHeader());
    }
}
