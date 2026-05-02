package org.owasp.astf.integrations.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.integrations.core.CIEnvironment;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Security configuration for CI/CD integrations.
 * This class provides security-focused utilities for CI/CD integrations,
 * including configuration validation, sensitive data masking, and
 * result sanitization.
 */
public class SecurityConfiguration {
    private static final Logger logger = LogManager.getLogger(SecurityConfiguration.class);

    // Patterns for identifying sensitive information
    private static final Pattern[] SENSITIVE_PATTERNS = {
            Pattern.compile("(?i)\\b(api[_-]?key|apikey|token|secret|password|credential|access[_-]?key)\\b"),
            Pattern.compile("(?i)bearer\\s+[a-zA-Z0-9\\-_\\.]+"),
            Pattern.compile("(?i)basic\\s+[a-zA-Z0-9\\+/=]+"),
            Pattern.compile("[a-zA-Z0-9_\\-\\.+/]{40,}") // Long random strings likely to be tokens
    };

    // Headers that should be masked in logs and reports
    private static final List<String> SENSITIVE_HEADERS = List.of(
            "authorization",
            "cookie",
            "x-api-key",
            "api-key",
            "token",
            "secret",
            "password"
    );

    /**
     * Private constructor to prevent instantiation.
     */
    private SecurityConfiguration() {
        // Utility class should not be instantiated
    }

    /**
     * Validates a scan configuration for security issues.
     *
     * @param config The configuration to validate
     * @param environment The CI environment
     * @return A map of validation issue keys to error messages, empty if no issues
     */
    public static Map<String, String> validateConfig(ScanConfig config, CIEnvironment environment) {
        Map<String, String> issues = new HashMap<>();

        // Check for injections in target URL
        String targetUrl = config.getTargetUrl();
        if (targetUrl != null && (
                targetUrl.contains("$") ||
                        targetUrl.contains("`") ||
                        targetUrl.contains("&") && targetUrl.contains(";"))) {
            issues.put("targetUrl", "Target URL contains potentially dangerous characters");
        }

        // Check for sensitive information in target URL
        if (targetUrl != null && containsSensitiveInformation(targetUrl)) {
            issues.put("targetUrlSensitive", "Target URL may contain sensitive information");
        }

        // Check for clear-text credentials in headers
        for (Map.Entry<String, String> header : config.getHeaders().entrySet()) {
            String headerName = header.getKey().toLowerCase();
            String headerValue = header.getValue();

            if (SENSITIVE_HEADERS.contains(headerName) &&
                    !headerValue.equals("********") &&
                    !headerValue.equals("[REDACTED]")) {
                issues.put("clearTextCredentials", "Headers contain clear-text credentials");
                break;
            }
        }

        // Warn about unrestricted scan scope in public CI environment
        if (isPotentiallyPublicEnvironment(environment) &&
                config.isDiscoveryEnabled() &&
                config.getEndpoints().isEmpty()) {
            issues.put("unrestrictedScope", "Unrestricted scan scope in potentially public CI environment");
        }

        return issues;
    }

    /**
     * Sanitizes headers to mask sensitive information.
     *
     * @param headers The headers to sanitize
     * @return Sanitized headers
     */
    public static Map<String, String> sanitizeHeaders(Map<String, String> headers) {
        Map<String, String> sanitized = new HashMap<>();

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();

            if (isSensitiveHeader(name)) {
                sanitized.put(name, "********");
            } else if (containsSensitiveInformation(value)) {
                sanitized.put(name, maskSensitiveInformation(value));
            } else {
                sanitized.put(name, value);
            }
        }

        return sanitized;
    }

    /**
     * Sanitizes scan results to mask sensitive information.
     *
     * @param results The scan results to sanitize
     * @return Sanitized scan results
     */
    public static ScanResult sanitizeResults(ScanResult results) {
        // Create sanitized findings
        List<Finding> sanitizedFindings = results.getFindings().stream()
                .map(finding -> {
                    Finding sanitized = new Finding(
                            finding.getId(),
                            finding.getTitle(),
                            maskSensitiveInformation(finding.getDescription()),
                            finding.getSeverity(),
                            finding.getTestCaseId(),
                            finding.getEndpoint(),
                            maskSensitiveInformation(finding.getRemediation())
                    );

                    if (finding.getRequestDetails() != null) {
                        sanitized.setRequestDetails(maskSensitiveInformation(finding.getRequestDetails()));
                    }

                    if (finding.getResponseDetails() != null) {
                        sanitized.setResponseDetails(maskSensitiveInformation(finding.getResponseDetails()));
                    }

                    if (finding.getEvidence() != null) {
                        sanitized.setEvidence(maskSensitiveInformation(finding.getEvidence()));
                    }

                    return sanitized;
                })
                .collect(Collectors.toList());

        // Create sanitized scan result
        ScanResult sanitized = new ScanResult(results.getTargetUrl(), sanitizedFindings);
        sanitized.setScanStartTime(results.getScanStartTime());
        sanitized.setScanEndTime(results.getScanEndTime());

        return sanitized;
    }

    /**
     * Checks if a string contains sensitive information.
     *
     * @param text The text to check
     * @return true if the text contains sensitive information, false otherwise
     */
    public static boolean containsSensitiveInformation(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        for (Pattern pattern : SENSITIVE_PATTERNS) {
            if (pattern.matcher(text).find()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Masks sensitive information in a string.
     *
     * @param text The text to mask
     * @return The masked text
     */
    public static String maskSensitiveInformation(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }

        String masked = text;

        for (Pattern pattern : SENSITIVE_PATTERNS) {
            masked = pattern.matcher(masked).replaceAll("********");
        }

        return masked;
    }

    /**
     * Checks if a header is sensitive and should be masked.
     *
     * @param headerName The header name
     * @return true if the header is sensitive, false otherwise
     */
    private static boolean isSensitiveHeader(String headerName) {
        String lower = headerName.toLowerCase();
        return SENSITIVE_HEADERS.contains(lower);
    }

    /**
     * Checks if the environment is potentially public (e.g., a fork PR).
     *
     * @param environment The CI environment
     * @return true if the environment is potentially public, false otherwise
     */
    private static boolean isPotentiallyPublicEnvironment(CIEnvironment environment) {
        // For GitHub Actions, check if we're in a PR from a fork
        if (environment.getPlatformName().equals("GitHub Actions")) {
            boolean isPR = environment.isPullRequest();

            // Check if repository owner is different from PR creator
            if (isPR) {
                String actorName = environment.getEnvironmentVariable("GITHUB_ACTOR").orElse("");
                String repoName = environment.getRepositoryName();

                if (!repoName.isEmpty() && repoName.contains("/")) {
                    String repoOwner = repoName.split("/")[0];
                    return !actorName.isEmpty() && !repoOwner.equals(actorName);
                }
            }
        }

        // For other platforms, implement similar checks

        // Default to false for unknown environments
        return false;
    }

    /**
     * Creates security recommendations based on a scan configuration.
     *
     * @param config The scan configuration
     * @param environment The CI environment
     * @return A list of security recommendations
     */
    public static List<String> createSecurityRecommendations(ScanConfig config, CIEnvironment environment) {
        List<String> recommendations = new ArrayList<>();

        // Check for authentication
        if (config.getHeaders().keySet().stream()
                .noneMatch(key -> key.equalsIgnoreCase("Authorization"))) {
            recommendations.add("Consider using authentication to scan authenticated API endpoints");
        }

        // Check for rate limiting
        if (config.getThreads() > 20) {
            recommendations.add("High thread count may trigger rate limiting. Consider reducing threads.");
        }

        // Check for discovery in public environment
        if (isPotentiallyPublicEnvironment(environment) && config.isDiscoveryEnabled()) {
            recommendations.add("Consider disabling endpoint discovery in public environments to avoid security risks");
        }

        // Recommend output sanitization
        if (environment.isPullRequest()) {
            recommendations.add("Ensure scan results are sanitized before exposing in pull request comments");
        }

        // Recommend secure credential handling
        recommendations.add("Store API credentials in secure environment variables or secrets management");

        return recommendations;
    }
}