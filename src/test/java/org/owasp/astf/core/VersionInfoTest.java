package org.owasp.astf.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("VersionInfo unit tests")
class VersionInfoTest {

    @Test
    @DisplayName("Resolves a real version from the build-time-filtered version.properties resource")
    void testResolvesRealVersion() {
        String version = VersionInfo.getVersion();

        assertNotNull(version);
        assertFalse(version.isBlank());
        assertFalse(version.startsWith("${"),
                "Should never surface the unresolved Maven placeholder literally");
        assertTrue(version.matches("\\d+\\.\\d+\\.\\d+(-.*)?|unknown"),
                "Should be a real semver-shaped version (or the documented 'unknown' fallback), got: " + version);
    }

    @Test
    @DisplayName("getVersion() is stable across repeated calls")
    void testVersionIsStable() {
        assertEquals(VersionInfo.getVersion(), VersionInfo.getVersion());
    }
}
