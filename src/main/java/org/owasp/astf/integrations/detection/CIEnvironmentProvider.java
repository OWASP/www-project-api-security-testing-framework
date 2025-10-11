package org.owasp.astf.integrations.detection;

import org.owasp.astf.integrations.core.CIEnvironment;

/**
 * Provider interface for CI/CD environments.
 * Implementations of this interface detect and provide information about
 * specific CI/CD platforms.
 */
public interface CIEnvironmentProvider {

    /**
     * Gets the name of the CI/CD platform that this provider supports.
     *
     * @return The platform name (e.g., "GitHub Actions", "Jenkins")
     */
    String getName();

    /**
     * Checks if this provider is applicable to the current environment.
     * This method should detect if the tool is running in the CI/CD platform
     * that this provider supports.
     *
     * @return true if the current environment matches this provider, false otherwise
     */
    boolean isApplicable();

    /**
     * Gets the CI environment information.
     * This method should only be called if isApplicable() returns true.
     *
     * @return The CI environment details
     */
    CIEnvironment getEnvironment();
}