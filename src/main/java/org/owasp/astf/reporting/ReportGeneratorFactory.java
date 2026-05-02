package org.owasp.astf.reporting;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;

/**
 * Factory for creating report generators based on the desired output format.
 * <p>
 * This factory creates the appropriate report generator based on the output
 * format specified in the scan configuration. It supports all standard output
 * formats such as JSON, HTML, XML, and SARIF.
 * </p>
 */
public class ReportGeneratorFactory {
    private static final Logger logger = LogManager.getLogger(ReportGeneratorFactory.class);

    /**
     * Private constructor to prevent instantiation.
     */
    private ReportGeneratorFactory() {
        // Utility class should not be instantiated
    }

    /**
     * Creates a report generator for the specified output format.
     *
     * @param format The desired output format
     * @return A report generator for the specified format
     * @throws IllegalArgumentException If the format is not supported
     */
    public static ReportGenerator createGenerator(ScanConfig.OutputFormat format) {
        logger.debug("Creating report generator for format: {}", format);

        return switch (format) {
            case JSON -> new JsonReportGenerator();
            case HTML -> new HtmlReportGenerator();
            case XML -> new XmlReportGenerator();
            case SARIF -> new SarifReportGenerator();
            default -> throw new IllegalArgumentException("Unsupported output format: " + format);
        };
    }

    /**
     * Creates a report generator based on the file extension.
     *
     * @param filePath The output file path
     * @return A report generator for the specified file extension
     * @throws IllegalArgumentException If the file extension is not supported
     */
    public static ReportGenerator createGeneratorFromFilePath(String filePath) {
        logger.debug("Creating report generator for file: {}", filePath);

        String lowerPath = filePath.toLowerCase();

        if (lowerPath.endsWith(".json")) {
            return new JsonReportGenerator();
        } else if (lowerPath.endsWith(".html") || lowerPath.endsWith(".htm")) {
            return new HtmlReportGenerator();
        } else if (lowerPath.endsWith(".xml")) {
            return new XmlReportGenerator();
        } else if (lowerPath.endsWith(".sarif")) {
            return new SarifReportGenerator();
        } else {
            throw new IllegalArgumentException("Unsupported file extension: " + filePath);
        }
    }
}