package org.owasp.astf.core.result;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Contains the complete results of a security scan.
 */
public class ScanResult {
    private final String targetUrl;
    private LocalDateTime scanStartTime;
    private LocalDateTime scanEndTime;
    private final List<Finding> findings;

    public ScanResult(String targetUrl, List<Finding> findings) {
        this.targetUrl = targetUrl;
        this.findings = findings;
        this.scanStartTime = LocalDateTime.now().minusMinutes(1); // Placeholder
        this.scanEndTime = LocalDateTime.now(); // Placeholder
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public LocalDateTime getScanStartTime() {
        return scanStartTime;
    }

    public void setScanStartTime(LocalDateTime scanStartTime) {
        this.scanStartTime = scanStartTime;
    }

    public LocalDateTime getScanEndTime() {
        return scanEndTime;
    }

    public void setScanEndTime(LocalDateTime scanEndTime) {
        this.scanEndTime = scanEndTime;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    /**
     * Gets a summary of findings grouped by severity.
     *
     * @return A map of severity to count
     */
    public Map<Severity, Long> getSeveritySummary() {
        return findings.stream()
                .collect(Collectors.groupingBy(Finding::getSeverity, Collectors.counting()));
    }

    /**
     * Gets the total number of findings.
     *
     * @return The number of findings
     */
    public int getTotalFindingsCount() {
        return findings.size();
    }
}