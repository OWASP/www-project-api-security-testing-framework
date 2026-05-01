package org.owasp.astf.integration;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.reporting.SarifReportGenerator;

/**
 * Integration for GitHub Actions CI/CD environments.
 *
 * <p>When running inside a GitHub Actions workflow ({@code GITHUB_ACTIONS=true}), this
 * integration:
 * <ul>
 *   <li>Emits workflow commands ({@code ::error::} / {@code ::warning::}) for each finding
 *       so GitHub renders inline annotations on the summary page.</li>
 *   <li>Writes a SARIF report that GitHub Code Scanning can upload.</li>
 *   <li>Optionally posts a Markdown summary as a PR comment when
 *       {@code GITHUB_TOKEN} and {@code GITHUB_PR_NUMBER} are set.</li>
 * </ul>
 */
public class GitHubActionsIntegration implements Integration {
    private static final Logger logger = LogManager.getLogger(GitHubActionsIntegration.class);

    private final PrintStream output;
    private final Map<String, String> environment;
    private ScanConfig config;

    /** Production constructor — reads real environment variables and writes to stdout. */
    public GitHubActionsIntegration() {
        this(System.out, System.getenv());
    }

    /** Testing constructor — injectable output stream and environment map. */
    GitHubActionsIntegration(PrintStream output, Map<String, String> environment) {
        this.output = output;
        this.environment = environment;
    }

    @Override
    public String getName() {
        return "GitHub Actions";
    }

    @Override
    public boolean isAvailable() {
        return "true".equalsIgnoreCase(environment.get("GITHUB_ACTIONS"));
    }

    @Override
    public void initialize(ScanConfig config) {
        this.config = config;
        logger.info("GitHub Actions integration initialized — SARIF output preferred");
    }

    @Override
    public void processResults(ScanResult result) {
        emitAnnotations(result);
        generateSarif(result);

        String token = environment.get("GITHUB_TOKEN");
        String prNumber = environment.get("GITHUB_PR_NUMBER");
        if (token != null && !token.isBlank() && prNumber != null && !prNumber.isBlank()) {
            createPrComment(result, token, prNumber);
        }
    }

    // -------------------------------------------------------------------------
    // Workflow annotations
    // -------------------------------------------------------------------------

    private void emitAnnotations(ScanResult result) {
        for (Finding finding : result.getFindings()) {
            String level = toAnnotationLevel(finding.getSeverity());
            // GitHub Actions workflow command format: ::level title=<title>::<message>
            output.printf("::%s title=%s::%s%n",
                    level,
                    escapeWorkflowData(finding.getTitle()),
                    escapeWorkflowData(finding.getDescription().trim()));
        }
    }

    private String toAnnotationLevel(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            default -> "notice";
        };
    }

    // -------------------------------------------------------------------------
    // SARIF generation
    // -------------------------------------------------------------------------

    private void generateSarif(ScanResult result) {
        if (config == null) return;

        String sarifPath = (config.getOutputFile() != null && !config.getOutputFile().isBlank())
                ? config.getOutputFile()
                : "results.sarif";

        try {
            new SarifReportGenerator().generateToFile(result, sarifPath);
            logger.info("SARIF report written to: {}", sarifPath);
        } catch (IOException e) {
            logger.warn("Failed to write SARIF report: {}", e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // PR comment creation
    // -------------------------------------------------------------------------

    private void createPrComment(ScanResult result, String token, String prNumber) {
        String repo = environment.get("GITHUB_REPOSITORY");
        if (repo == null || repo.isBlank()) {
            logger.warn("GITHUB_REPOSITORY not set — cannot post PR comment");
            return;
        }

        String apiUrl = "https://api.github.com/repos/" + repo + "/issues/" + prNumber + "/comments";
        String body = buildPrCommentBody(result);

        try {
            HttpClient httpClient = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"body\":" + toJsonString(body) + "}"))
                    .build();
            httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            logger.info("PR comment posted for PR #{}", prNumber);
        } catch (Exception e) {
            logger.warn("Failed to create PR comment: {}", e.getMessage());
        }
    }

    String buildPrCommentBody(ScanResult result) {
        Map<Severity, Long> summary = result.getSeveritySummary();
        StringBuilder sb = new StringBuilder();
        sb.append("## OWASP API Security Testing Framework Results\n\n");
        sb.append("**Target:** ").append(result.getTargetUrl()).append("\n");
        sb.append("**Total Findings:** ").append(result.getTotalFindingsCount()).append("\n\n");
        sb.append("| Severity | Count |\n|---|---|\n");
        for (Severity s : Severity.values()) {
            sb.append("| ").append(s).append(" | ").append(summary.getOrDefault(s, 0L)).append(" |\n");
        }
        if (!result.getFindings().isEmpty()) {
            sb.append("\n### Findings\n\n");
            for (Finding f : result.getFindings()) {
                sb.append("- **[").append(f.getSeverity()).append("] ")
                        .append(f.getTitle()).append("** — ").append(f.getEndpoint()).append("\n");
            }
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Escapes characters that have special meaning in GitHub Actions workflow commands. */
    private String escapeWorkflowData(String s) {
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A");
    }

    private String toJsonString(String s) {
        return "\"" + s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                + "\"";
    }
}
