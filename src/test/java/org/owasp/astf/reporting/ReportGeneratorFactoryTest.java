package org.owasp.astf.reporting;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.astf.core.config.ScanConfig;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ReportGeneratorFactory Tests")
class ReportGeneratorFactoryTest {

    @Test
    @DisplayName("Should create JsonReportGenerator for JSON format")
    void testCreateJson() {
        ReportGenerator gen = ReportGeneratorFactory.create(ScanConfig.OutputFormat.JSON);
        assertInstanceOf(JsonReportGenerator.class, gen);
    }

    @Test
    @DisplayName("Should create XmlReportGenerator for XML format")
    void testCreateXml() {
        ReportGenerator gen = ReportGeneratorFactory.create(ScanConfig.OutputFormat.XML);
        assertInstanceOf(XmlReportGenerator.class, gen);
    }

    @Test
    @DisplayName("Should create HtmlReportGenerator for HTML format")
    void testCreateHtml() {
        ReportGenerator gen = ReportGeneratorFactory.create(ScanConfig.OutputFormat.HTML);
        assertInstanceOf(HtmlReportGenerator.class, gen);
    }

    @Test
    @DisplayName("Should create SarifReportGenerator for SARIF format")
    void testCreateSarif() {
        ReportGenerator gen = ReportGeneratorFactory.create(ScanConfig.OutputFormat.SARIF);
        assertInstanceOf(SarifReportGenerator.class, gen);
    }

    @Test
    @DisplayName("Should default to JSON when null format provided")
    void testCreateNull() {
        ReportGenerator gen = ReportGeneratorFactory.create((ScanConfig.OutputFormat) null);
        assertInstanceOf(JsonReportGenerator.class, gen);
    }

    @Test
    @DisplayName("Should use format from ScanConfig")
    void testCreateFromConfig() {
        ScanConfig config = new ScanConfig();
        config.setOutputFormat(ScanConfig.OutputFormat.HTML);
        ReportGenerator gen = ReportGeneratorFactory.create(config);
        assertInstanceOf(HtmlReportGenerator.class, gen);
    }
}
