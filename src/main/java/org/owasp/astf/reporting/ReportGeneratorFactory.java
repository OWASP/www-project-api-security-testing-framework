package org.owasp.astf.reporting;

import org.owasp.astf.core.config.ScanConfig;

/**
 * Factory that creates the appropriate {@link ReportGenerator} based on the configured output format.
 */
public class ReportGeneratorFactory {

    private ReportGeneratorFactory() {}

    /**
     * Creates a report generator matching the format configured in {@code config}.
     *
     * @param config The scan configuration
     * @return The appropriate ReportGenerator
     */
    public static ReportGenerator create(ScanConfig config) {
        return create(config.getOutputFormat());
    }

    /**
     * Creates a report generator for the given output format.
     *
     * @param format The desired output format
     * @return The appropriate ReportGenerator
     */
    public static ReportGenerator create(ScanConfig.OutputFormat format) {
        if (format == null) {
            return new JsonReportGenerator();
        }
        return switch (format) {
            case JSON  -> new JsonReportGenerator();
            case XML   -> new XmlReportGenerator();
            case HTML  -> new HtmlReportGenerator();
            case SARIF -> new SarifReportGenerator();
        };
    }
}
