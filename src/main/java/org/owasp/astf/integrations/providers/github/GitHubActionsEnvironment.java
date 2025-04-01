package org.owasp.astf.integrations.providers.github;

import org.owasp.astf.integrations.core.CIEnvironment;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Implementation of CIEnvironment for GitHub Actions.
 * This class provides GitHub Actions-specific environment information.
 */
public class GitHubActionsEnvironment implements CIEnvironment {

    private static final String PLATFORM_NAME = "GitHub Actions";
    private final Map<String, String> environmentVariables;

    /**
     * Creates a new GitHub Actions environment.
     */
    public GitHubActionsEnvironment() {
        this.environmentVariables = new HashMap<>();
        loadEnvironmentVariables();
    }

    /**
     * Loads relevant environment variables.
     */
    private void loadEnvironmentVariables() {
        // Load environment variables related to GitHub Actions
        for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("GITHUB_") || key.startsWith("ACTIONS_") ||
                    key.equals("CI") || key.equals("RUNNER_NAME")) {
                environmentVariables.put(key, entry.getValue());
            }
        }
    }

    @Override
    public String getPlatformName() {
        return PLATFORM_NAME;
    }

    @Override
    public Optional<String> getPlatformVersion() {
        return Optional.ofNullable(environmentVariables.get("ACTIONS_RUNNER_VERSION"));
    }

    @Override
    public String getBuildId() {
        return environmentVariables.getOrDefault("GITHUB_RUN_ID", "unknown");
    }

    @Override
    public String getRepositoryName() {
        return environmentVariables.getOrDefault("GITHUB_REPOSITORY", "unknown");
    }

    @Override
    public String getBranchName() {
        return environmentVariables.getOrDefault("GITHUB_REF_NAME", "unknown");
    }

    @Override
    public String getCommitId() {
        return environmentVariables.getOrDefault("GITHUB_SHA", "unknown");
    }

    @Override
    public Map<String, String> getEnvironmentVariables() {
        return new HashMap<>(environmentVariables);
    }

    @Override
    public Optional<String> getEnvironmentVariable(String name) {
        return Optional.ofNullable(environmentVariables.get(name));
    }

    @Override
    public boolean isPullRequest() {
        String eventName = environmentVariables.getOrDefault("GITHUB_EVENT_NAME", "");
        return "pull_request".equals(eventName) || "pull_request_target".equals(eventName);
    }

    @Override
    public Optional<String> getPullRequestId() {
        if (!isPullRequest()) {
            return Optional.empty();
        }

        // Extract PR number from GITHUB_REF
        String ref = environmentVariables.getOrDefault("GITHUB_REF", "");
        if (ref.startsWith("refs/pull/") && ref.endsWith("/merge")) {
            String prNumber = ref.substring(10, ref.length() - 7);
            return Optional.of(prNumber);
        }

        return Optional.empty();
    }

    @Override
    public boolean supportsResultUploads() {
        return true;
    }

    @Override
    public Optional<String> getBuildUrl() {
        String serverUrl = environmentVariables.getOrDefault("GITHUB_SERVER_URL", "");
        String repository = environmentVariables.getOrDefault("GITHUB_REPOSITORY", "");
        String runId = environmentVariables.getOrDefault("GITHUB_RUN_ID", "");

        if (!serverUrl.isEmpty() && !repository.isEmpty() && !runId.isEmpty()) {
            return Optional.of(String.format("%s/%s/actions/runs/%s", serverUrl, repository, runId));
        }

        return Optional.empty();
    }

    @Override
    public String getWorkspaceDirectory() {
        return environmentVariables.getOrDefault("GITHUB_WORKSPACE",
                Paths.get("").toAbsolutePath().toString());
    }

    /**
     * Gets the GitHub Actions workflow name.
     *
     * @return The workflow name
     */
    public String getWorkflowName() {
        return environmentVariables.getOrDefault("GITHUB_WORKFLOW", "unknown");
    }

    /**
     * Gets the GitHub Actions event that triggered the workflow.
     *
     * @return The event name
     */
    public String getEventName() {
        return environmentVariables.getOrDefault("GITHUB_EVENT_NAME", "unknown");
    }

    /**
     * Gets the GitHub Actor (username) that triggered the workflow.
     *
     * @return The GitHub username
     */
    public String getActor() {
        return environmentVariables.getOrDefault("GITHUB_ACTOR", "unknown");
    }

    /**
     * Gets the path to the GitHub event file.
     *
     * @return The event file path
     */
    public String getEventPath() {
        return environmentVariables.getOrDefault("GITHUB_EVENT_PATH", "");
    }

    /**
     * Gets the GitHub API URL.
     *
     * @return The API URL
     */
    public String getApiUrl() {
        return environmentVariables.getOrDefault("GITHUB_API_URL", "https://api.github.com");
    }

    /**
     * Gets the GitHub Actions workflow ref.
     *
     * @return The workflow ref
     */
    public String getWorkflowRef() {
        return environmentVariables.getOrDefault("GITHUB_REF", "");
    }

    /**
     * Gets the GitHub Actions repository owner.
     *
     * @return The repository owner
     */
    public String getRepositoryOwner() {
        String repository = getRepositoryName();
        if (repository.contains("/")) {
            return repository.split("/")[0];
        }
        return "";
    }

    /**
     * Gets the GitHub Actions repository name without owner.
     *
     * @return The repository name
     */
    public String getRepositoryNameOnly() {
        String repository = getRepositoryName();
        if (repository.contains("/")) {
            return repository.split("/")[1];
        }
        return repository;
    }

    /**
     * Gets the GitHub Actions job name.
     *
     * @return The job name
     */
    public String getJobName() {
        return environmentVariables.getOrDefault("GITHUB_JOB", "");
    }

    /**
     * Checks if the current workflow is running on a forked repository.
     *
     * @return true if running on a fork, false otherwise
     */
    public boolean isForkedRepository() {
        if (!isPullRequest()) {
            return false;
        }

        String actor = getActor();
        String owner = getRepositoryOwner();

        return !actor.isEmpty() && !owner.isEmpty() && !actor.equals(owner);
    }

    /**
     * Gets the GitHub Actions runner OS.
     *
     * @return The runner OS
     */
    public String getRunnerOs() {
        return environmentVariables.getOrDefault("RUNNER_OS", "");
    }
}