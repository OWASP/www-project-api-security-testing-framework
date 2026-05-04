package org.owasp.astf.core.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.astf.core.EndpointInfo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ConfigLoader Tests")
class ConfigLoaderTest {

    private ConfigLoader loader;

    @BeforeEach
    void setUp() {
        loader = new ConfigLoader();
    }

    // -------------------------------------------------------------------------
    // YAML loading
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should load YAML configuration file")
    void testLoadYaml(@TempDir Path tempDir) throws IOException {
        String yaml = """
                targetUrl: https://api.example.com
                threads: 5
                outputFormat: HTML
                verbose: true
                headers:
                  X-API-Key: secret123
                """;
        Path yamlFile = tempDir.resolve("config.yaml");
        Files.writeString(yamlFile, yaml);

        ScanConfig config = loader.loadFromFile(yamlFile.toString());

        assertNotNull(config);
        assertTrue(config.getTargetUrl().startsWith("https://api.example.com"));
        assertEquals(5, config.getThreads());
        assertEquals(ScanConfig.OutputFormat.HTML, config.getOutputFormat());
        assertTrue(config.isVerbose());
        assertEquals("secret123", config.getHeaders().get("X-API-Key"));
    }

    @Test
    @DisplayName("Should load .yml extension as YAML")
    void testLoadYmlExtension(@TempDir Path tempDir) throws IOException {
        String yaml = "targetUrl: https://api.example.com\n";
        Path ymlFile = tempDir.resolve("config.yml");
        Files.writeString(ymlFile, yaml);

        ScanConfig config = loader.loadFromFile(ymlFile.toString());

        assertTrue(config.getTargetUrl().startsWith("https://api.example.com"));
    }

    @Test
    @DisplayName("Should load proxy settings from YAML")
    void testLoadYamlProxySettings(@TempDir Path tempDir) throws IOException {
        String yaml = """
                targetUrl: https://api.example.com
                proxy:
                  host: proxy.corp.com
                  port: 3128
                  username: proxyuser
                  password: proxypass
                """;
        Path yamlFile = tempDir.resolve("config.yaml");
        Files.writeString(yamlFile, yaml);

        ScanConfig config = loader.loadFromFile(yamlFile.toString());

        assertEquals("proxy.corp.com", config.getProxyHost());
        assertEquals(3128, config.getProxyPort());
        assertEquals("proxyuser", config.getProxyUsername());
        assertEquals("proxypass", config.getProxyPassword());
    }

    @Test
    @DisplayName("Should load test case selection from YAML")
    void testLoadTestCaseSelection(@TempDir Path tempDir) throws IOException {
        String yaml = """
                targetUrl: https://api.example.com
                enableTestCases:
                  - ASTF-API1-2023
                  - ASTF-API2-2023
                disableTestCases:
                  - ASTF-API10-2023
                """;
        Path yamlFile = tempDir.resolve("config.yaml");
        Files.writeString(yamlFile, yaml);

        ScanConfig config = loader.loadFromFile(yamlFile.toString());

        assertEquals(2, config.getEnabledTestCaseIds().size());
        assertTrue(config.getEnabledTestCaseIds().contains("ASTF-API1-2023"));
        assertEquals(1, config.getDisabledTestCaseIds().size());
        assertTrue(config.getDisabledTestCaseIds().contains("ASTF-API10-2023"));
    }

    // -------------------------------------------------------------------------
    // JSON loading
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should load JSON configuration file")
    void testLoadJson(@TempDir Path tempDir) throws IOException {
        String json = """
                {
                  "targetUrl": "https://api.example.com",
                  "threads": 20,
                  "outputFormat": "SARIF",
                  "timeoutMinutes": 60
                }
                """;
        Path jsonFile = tempDir.resolve("config.json");
        Files.writeString(jsonFile, json);

        ScanConfig config = loader.loadFromFile(jsonFile.toString());

        assertTrue(config.getTargetUrl().startsWith("https://api.example.com"));
        assertEquals(20, config.getThreads());
        assertEquals(ScanConfig.OutputFormat.SARIF, config.getOutputFormat());
        assertEquals(60, config.getTimeoutMinutes());
    }

    @Test
    @DisplayName("Should load proxy and basic auth from JSON")
    void testLoadJsonProxyAndAuth(@TempDir Path tempDir) throws IOException {
        String json = """
                {
                  "targetUrl": "https://api.example.com",
                  "proxy": {"host": "proxy.corp.com", "port": 8080},
                  "basicAuth": {"username": "user", "password": "pass"}
                }
                """;
        Path jsonFile = tempDir.resolve("config.json");
        Files.writeString(jsonFile, json);

        ScanConfig config = loader.loadFromFile(jsonFile.toString());

        assertEquals("proxy.corp.com", config.getProxyHost());
        assertEquals(8080, config.getProxyPort());
        assertEquals("user", config.getBasicAuthUsername());
        assertEquals("pass", config.getBasicAuthPassword());
    }

    // -------------------------------------------------------------------------
    // Properties loading
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should load properties configuration file")
    void testLoadProperties(@TempDir Path tempDir) throws IOException {
        String props = """
                targetUrl=https://api.example.com
                threads=3
                outputFormat=XML
                proxy.host=proxy.example.com
                proxy.port=8080
                """;
        Path propsFile = tempDir.resolve("config.properties");
        Files.writeString(propsFile, props);

        ScanConfig config = loader.loadFromFile(propsFile.toString());

        assertTrue(config.getTargetUrl().startsWith("https://api.example.com"));
        assertEquals(3, config.getThreads());
        assertEquals(ScanConfig.OutputFormat.XML, config.getOutputFormat());
        assertEquals("proxy.example.com", config.getProxyHost());
        assertEquals(8080, config.getProxyPort());
    }

    @Test
    @DisplayName("Should load custom headers from properties file")
    void testLoadPropertiesHeaders(@TempDir Path tempDir) throws IOException {
        String props = """
                targetUrl=https://api.example.com
                header.Authorization=Bearer mytoken
                header.X-Custom=value
                """;
        Path propsFile = tempDir.resolve("config.properties");
        Files.writeString(propsFile, props);

        ScanConfig config = loader.loadFromFile(propsFile.toString());

        assertEquals("Bearer mytoken", config.getHeaders().get("Authorization"));
        assertEquals("value", config.getHeaders().get("X-Custom"));
    }

    // -------------------------------------------------------------------------
    // Endpoint file loading
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should load endpoints from text file ignoring comments")
    void testLoadEndpointsFromFile(@TempDir Path tempDir) throws IOException {
        String content = """
                # Comment line
                GET /api/users
                POST /api/users
                GET /api/products
                """;
        Path endpointsFile = tempDir.resolve("endpoints.txt");
        Files.writeString(endpointsFile, content);

        List<EndpointInfo> endpoints = loader.loadEndpointsFromFile(endpointsFile.toString());

        assertEquals(3, endpoints.size());
        assertEquals("GET", endpoints.get(0).getMethod());
        assertEquals("/api/users", endpoints.get(0).getPath());
        assertEquals("POST", endpoints.get(1).getMethod());
    }

    @Test
    @DisplayName("Should throw IOException for missing endpoint file")
    void testMissingEndpointFile() {
        assertThrows(IOException.class,
                () -> loader.loadEndpointsFromFile("/nonexistent/endpoints.txt"));
    }

    // -------------------------------------------------------------------------
    // System properties
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should apply system properties with prefix")
    void testLoadFromSystemProperties() {
        System.setProperty("astf.targeturl", "https://sysprop.example.com");
        System.setProperty("astf.verbose", "true");
        System.setProperty("astf.threads", "7");
        try {
            ScanConfig config = new ScanConfig();
            loader.loadFromSystemProperties("astf.", config);

            assertEquals("https://sysprop.example.com/", config.getTargetUrl());
            assertTrue(config.isVerbose());
            assertEquals(7, config.getThreads());
        } finally {
            System.clearProperty("astf.targeturl");
            System.clearProperty("astf.verbose");
            System.clearProperty("astf.threads");
        }
    }

    // -------------------------------------------------------------------------
    // Error handling
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Should throw IOException for non-existent file")
    void testMissingFile() {
        assertThrows(IOException.class,
                () -> loader.loadFromFile("/nonexistent/path/config.yaml"));
    }

    @Test
    @DisplayName("Should throw IOException for unsupported file format")
    void testUnsupportedFormat(@TempDir Path tempDir) throws IOException {
        Path txtFile = tempDir.resolve("config.txt");
        Files.writeString(txtFile, "targetUrl=https://api.example.com");

        assertThrows(IOException.class, () -> loader.loadFromFile(txtFile.toString()));
    }

    @Test
    @DisplayName("Should keep default output format when YAML contains invalid value")
    void testInvalidOutputFormat(@TempDir Path tempDir) throws IOException {
        String yaml = """
                targetUrl: https://api.example.com
                outputFormat: INVALID_FORMAT
                """;
        Path yamlFile = tempDir.resolve("config.yaml");
        Files.writeString(yamlFile, yaml);

        ScanConfig config = loader.loadFromFile(yamlFile.toString());

        assertNotNull(config);
        assertEquals(ScanConfig.OutputFormat.JSON, config.getOutputFormat());
    }
}
