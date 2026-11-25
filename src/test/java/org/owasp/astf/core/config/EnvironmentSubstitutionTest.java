package org.owasp.astf.core.config;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("Config environment variable substitution")
class EnvironmentSubstitutionTest {

    private static ConfigLoader loaderWith(Map<String, String> env) {
        return new ConfigLoader(env::get);
    }

    private static Path write(Path dir, String name, String content) throws IOException {
        Path file = dir.resolve(name);
        Files.writeString(file, content);
        return file;
    }

    @Test
    @DisplayName("Should substitute placeholders in YAML values, nested maps and lists")
    void testYaml(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", """
                targetUrl: "$(API_BASE_URL)"
                headers:
                  Authorization: "Bearer $(API_TOKEN)"
                basicAuth:
                  username: "$(USER_NAME)"
                  password: "$(USER_PASS)"
                enableTestCases:
                  - "$(TEST_ID)"
                """);
        ScanConfig config = loaderWith(Map.of(
                "API_BASE_URL", "https://api.example.com",
                "API_TOKEN", "my-token",
                "USER_NAME", "alice",
                "USER_PASS", "p@ss",
                "TEST_ID", "ASTF-API1-2023")).loadFromFile(file.toString());

        assertEquals("https://api.example.com", config.getTargetUrl().replaceAll("/$", ""));
        assertEquals("Bearer my-token", config.getHeaders().get("Authorization"));
        assertEquals("alice", config.getBasicAuthUsername());
        assertEquals("p@ss", config.getBasicAuthPassword());
        assertEquals(java.util.List.of("ASTF-API1-2023"), config.getEnabledTestCaseIds());
    }

    @Test
    @DisplayName("Should substitute placeholders in JSON values")
    void testJson(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.json", "{\"targetUrl\": \"https://$(HOST)/v1\", \"threads\": 3}");
        ScanConfig config = loaderWith(Map.of("HOST", "staging.example.com")).loadFromFile(file.toString());

        assertTrue(config.getTargetUrl().startsWith("https://staging.example.com/v1"));
        assertEquals(3, config.getThreads());
    }

    @Test
    @DisplayName("Should substitute placeholders in properties values")
    void testProperties(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.properties", "targetUrl=https://$(HOST)\nheader.X-Key=$(KEY)\n");
        ScanConfig config = loaderWith(Map.of("HOST", "api.example.com", "KEY", "k1")).loadFromFile(file.toString());

        assertTrue(config.getTargetUrl().startsWith("https://api.example.com"));
        assertEquals("k1", config.getHeaders().get("X-Key"));
    }

    @Test
    @DisplayName("Should support several placeholders in one value")
    void testMultiplePlaceholders(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  X-Id: \"$(A)-$(B)\"\n");
        ScanConfig config = loaderWith(Map.of("A", "one", "B", "two")).loadFromFile(file.toString());

        assertEquals("one-two", config.getHeaders().get("X-Id"));
    }

    @Test
    @DisplayName("Should fail naming the variable and location when a variable is not set")
    void testUnsetVariable(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  Authorization: \"Bearer $(MISSING_TOKEN)\"\n");

        IOException e = assertThrows(IOException.class,
                () -> loaderWith(Map.of("OTHER", "value")).loadFromFile(file.toString()));

        assertTrue(e.getMessage().contains("MISSING_TOKEN"));
        assertTrue(e.getMessage().contains("headers.Authorization"));
    }

    @Test
    @DisplayName("Should never put resolved secret values in error messages")
    void testErrorDoesNotLeakValues(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  A: \"$(SECRET)\"\n  B: \"$(MISSING)\"\n");

        IOException e = assertThrows(IOException.class,
                () -> loaderWith(Map.of("SECRET", "s3cr3t-value")).loadFromFile(file.toString()));

        assertFalse(e.getMessage().contains("s3cr3t-value"));
    }

    @Test
    @DisplayName("Should treat a variable set to an empty string as set")
    void testEmptyValue(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  X-Opt: \"a$(EMPTY)b\"\n");
        ScanConfig config = loaderWith(Map.of("EMPTY", "")).loadFromFile(file.toString());

        assertEquals("ab", config.getHeaders().get("X-Opt"));
    }

    @Test
    @DisplayName("Should keep $$(NAME) as the literal text $(NAME)")
    void testEscape(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  X-Lit: \"$$(NOT_A_VAR)\"\n");
        ScanConfig config = loaderWith(Map.of()).loadFromFile(file.toString());

        assertEquals("$(NOT_A_VAR)", config.getHeaders().get("X-Lit"));
    }

    @Test
    @DisplayName("Should not re-expand placeholders inside resolved values")
    void testNoRecursiveExpansion(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  X-Tok: \"$(TOKEN)\"\n");
        ScanConfig config = loaderWith(Map.of("TOKEN", "ab$(OTHER)cd", "OTHER", "x")).loadFromFile(file.toString());

        assertEquals("ab$(OTHER)cd", config.getHeaders().get("X-Tok"));
    }

    @Test
    @DisplayName("Should leave values that are not valid placeholders untouched")
    void testNonPlaceholdersUntouched(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml",
                "headers:\n  A: \"cost $5 (approx)\"\n  B: \"$()\"\n  C: \"${HOME}\"\n  D: \"$(not valid)\"\n");
        ScanConfig config = loaderWith(Map.of()).loadFromFile(file.toString());

        assertEquals("cost $5 (approx)", config.getHeaders().get("A"));
        assertEquals("$()", config.getHeaders().get("B"));
        assertEquals("${HOME}", config.getHeaders().get("C"));
        assertEquals("$(not valid)", config.getHeaders().get("D"));
    }

    @Test
    @DisplayName("Should not substitute map keys")
    void testKeysUntouched(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  \"$(KEY)\": value\n");
        ScanConfig config = loaderWith(Map.of()).loadFromFile(file.toString());

        assertEquals("value", config.getHeaders().get("$(KEY)"));
    }

    @Test
    @DisplayName("Should substitute inside inline endpoint entries")
    void testInlineEndpoints(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", """
                endpoints:
                  - path: "/users/$(USER_ID)"
                    method: GET
                """);
        ScanConfig config = loaderWith(Map.of("USER_ID", "42")).loadFromFile(file.toString());

        assertEquals("/users/42", config.getEndpoints().get(0).getPath());
    }

    @Test
    @DisplayName("Should load the real process environment by default")
    void testDefaultEnvironment(@TempDir Path dir) throws IOException {
        Path file = write(dir, "config.yaml", "headers:\n  X-Name: \"$(ASTF_SURELY_NOT_SET_VARIABLE_7F3A)\"\n");

        assertThrows(IOException.class, () -> new ConfigLoader().loadFromFile(file.toString()));
    }
}
