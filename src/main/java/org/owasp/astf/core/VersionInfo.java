package org.owasp.astf.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Resolves the framework's own version at runtime from a build-time-generated
 * {@code version.properties} resource (filtered from {@code project.version} in {@code pom.xml}).
 *
 * <p>This is the single source of truth for the version string used in CLI output and every
 * generated report — previously each of those places hardcoded its own literal version string,
 * which silently went stale at every release (the shipped v2.0.0 jar still printed "v1.0.0").
 */
public final class VersionInfo {

    private static final String VERSION = resolveVersion();

    private VersionInfo() {
    }

    public static String getVersion() {
        return VERSION;
    }

    private static String resolveVersion() {
        try (InputStream in = VersionInfo.class.getResourceAsStream("/version.properties")) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                String version = props.getProperty("version");
                // Falls through to "unknown" if resource filtering didn't run (e.g. resource
                // read directly from an IDE's unfiltered output directory) and the placeholder
                // was never substituted, rather than reporting a literal "${project.version}".
                if (version != null && !version.isBlank() && !version.startsWith("${")) {
                    return version;
                }
            }
        } catch (IOException ignored) {
            // Falls through to "unknown" below.
        }
        return "unknown";
    }
}
