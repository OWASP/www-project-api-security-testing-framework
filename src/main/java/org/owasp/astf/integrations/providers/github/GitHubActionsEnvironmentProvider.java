package org.owasp.astf.integrations.providers.github;

import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.detection.CIEnvironmentProvider;

/**
 * Provider for GitHub Actions environment detection.
 * This class detects if the tool is running in GitHub Actions
 * and provides GitHub Actions-specific environment information.
 */
public class GitHubActionsEnvironmentProvider implements CIEnvironmentProvider {

    private static final String PROVIDER_NAME = "GitHub Actions";
    private GitHubActionsEnvironment environment;

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public boolean isApplicable() {
        // Check for GitHub Actions-specific environment variables
        String githubActions = System.getenv("GITHUB_ACTIONS");
        return "true".equalsIgnoreCase(githubActions);
    }

    @Override
    public CIEnvironment getEnvironment() {
        if (environment == null) {
            environment = new GitHubActionsEnvironment();
        }
        return environment;
    }
}