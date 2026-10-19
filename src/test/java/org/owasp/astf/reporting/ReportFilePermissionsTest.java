package org.owasp.astf.reporting;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@DisplayName("Report files are owner-only")
class ReportFilePermissionsTest {

    @TempDir
    Path tempDir;

    private static ScanResult sample() {
        Finding f = new Finding(UUID.randomUUID().toString(), "Title", "Desc", Severity.HIGH,
                "ASTF-API1-2023", "GET /x", "Fix");
        return new ScanResult("https://example.com", List.of(f));
    }

    private static void assumePosix() {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
    }

    private void check(ReportGenerator generator, String name) throws IOException {
        assumePosix();
        Path out = tempDir.resolve(name);
        generator.generateToFile(sample(), out.toString());
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(out)));
    }

    @Test
    void jsonReportIsOwnerOnly() throws IOException {
        check(new JsonReportGenerator(), "r.json");
    }

    @Test
    void htmlReportIsOwnerOnly() throws IOException {
        check(new HtmlReportGenerator(), "r.html");
    }

    @Test
    void sarifReportIsOwnerOnly() throws IOException {
        check(new SarifReportGenerator(), "r.sarif");
    }

    @Test
    void xmlReportIsOwnerOnly() throws IOException {
        check(new XmlReportGenerator(), "r.xml");
    }

    @Test
    void existingWorldReadableReportIsTightened() throws IOException {
        assumePosix();
        Path out = tempDir.resolve("existing.json");
        Files.writeString(out, "old");
        Files.setPosixFilePermissions(out, PosixFilePermissions.fromString("rw-r--r--"));
        new JsonReportGenerator().generateToFile(sample(), out.toString());
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(out)));
    }
}
