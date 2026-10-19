package org.owasp.astf.reporting;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/** Writes report files readable only by their owner where the filesystem supports POSIX permissions. */
final class ReportFileWriter {

    private static final Logger logger = LogManager.getLogger(ReportFileWriter.class);

    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

    private ReportFileWriter() {
    }

    static void write(Path path, String content) throws IOException {
        if (!Files.exists(path)) {
            try {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
            } catch (UnsupportedOperationException | FileAlreadyExistsException e) {
                // Non-POSIX filesystem or created concurrently; Files.write handles the file below.
            }
        }
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch (UnsupportedOperationException e) {
            // Non-POSIX filesystem: nothing to tighten.
        } catch (IOException e) {
            // E.g. an existing report owned by someone else: the report itself was written, so
            // failing the whole scan over the permission change would lose the results.
            logger.warn("Could not restrict permissions on report file {}: {}", path, e.getMessage());
        }
    }
}
