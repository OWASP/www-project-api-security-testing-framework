package org.owasp.astf.core.result;

/**
 * Represents a security finding discovered during a scan.
 */
public class Finding {
    private final String id;
    private final String title;
    private final String description;
    private final Severity severity;
    private final String testCaseId;
    private final String endpoint;
    private String requestDetails;
    private String responseDetails;
    private final String remediation;
    private String evidence;

    public Finding(String id, String title, String description, Severity severity, String testCaseId,
                   String endpoint, String remediation) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.testCaseId = testCaseId;
        this.endpoint = endpoint;
        this.remediation = remediation;
    }

    public String getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getTestCaseId() {
        return testCaseId;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getRequestDetails() {
        return requestDetails;
    }

    public void setRequestDetails(String requestDetails) {
        this.requestDetails = requestDetails;
    }

    public String getResponseDetails() {
        return responseDetails;
    }

    public void setResponseDetails(String responseDetails) {
        this.responseDetails = responseDetails;
    }

    public String getRemediation() {
        return remediation;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }
}
