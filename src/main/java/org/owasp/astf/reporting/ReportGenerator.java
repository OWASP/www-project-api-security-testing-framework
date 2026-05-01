package org.owasp.astf.reporting;

import java.io.IOException;

import org.owasp.astf.core.result.ScanResult;

/**
 * Interface for generating security scan reports in various formats.
 */
public interface ReportGenerator {

    /**
     * Generates a report from the scan result and returns it as a string.
     *
     * @param result The scan result to report on
     * @return The formatted report content
     * @throws IOException If report generation fails
     */
    String generate(ScanResult result) throws IOException;

    /**
     * Generates a report and writes it to the specified file path.
     *
     * @param result     The scan result to report on
     * @param outputPath The file path to write the report to
     * @throws IOException If report generation or writing fails
     */
    void generateToFile(ScanResult result, String outputPath) throws IOException;
}
