package org.owasp.astf.integrations.core;

import java.util.Map;
import java.util.Optional;

/**
 * Represents a CI/CD environment where the security testing is being executed.
 * This interface abstracts the details of different CI/CD platforms and provides
 * a uniform way to interact with them.
 */
public interface CIEnvironment {

    /**
     * Gets the name of the CI/CD platform.
     *
     * @return The name of the CI/CD platform (e.g., "GitHub Actions", "Jenkins")
     */
    String getPlatformName();

    /**
     * Gets the version of the CI/CD platform, if available.
     *
     * @return An Optional containing the version string, or empty if not available
     */
    Optional<String> getPlatformVersion();

    /**
     * Gets the unique identifier for the current build or workflow run.
     *
     * @return The build identifier
     */
    String getBuildId();

    /**
     * Gets the name of the repository being built.
     *
     * @return The repository name
     */
    String getRepositoryName();

    /**
     * Gets the current branch or reference being built.
     *
     * @return The branch or reference name
     */
    String getBranchName();

    /**
     * Gets the commit SHA or identifier for the current build.
     *
     * @return The commit identifier
     */
    String getCommitId();

    /**
     * Gets environment variables available in the CI/CD environment.
     * Sensitive environment variables may be redacted based on security settings.
     *
     * @return A map of environment variable names to values
     */
    Map<String, String> getEnvironmentVariables();

    /**
     * Gets the value of a specific environment variable.
     *
     * @param name The name of the environment variable
     * @return An Optional containing the value, or empty if not set
     */
    Optional<String> getEnvironmentVariable(String name);

    /**
     * Checks if the current build is triggered by a pull/merge request.
     *
     * @return true if the build is for a PR/MR, false otherwise
     */
    boolean isPullRequest();

    /**
     * Gets the pull/merge request number or identifier, if applicable.
     *
     * @return An Optional containing the PR/MR number, or empty if not applicable
     */
    Optional<String> getPullRequestId();

    /**
     * Checks if the current environment supports security scan result uploads.
     *
     * @return true if results can be uploaded to the CI/CD platform
     */
    boolean supportsResultUploads();

    /**
     * Gets the URL to the CI/CD build or workflow run, if available.
     *
     * @return An Optional containing the build URL, or empty if not available
     */
    Optional<String> getBuildUrl();

    /**
     * Gets the workspace directory where the build is running.
     *
     * @return The absolute path to the workspace directory
     */
    String getWorkspaceDirectory();
}