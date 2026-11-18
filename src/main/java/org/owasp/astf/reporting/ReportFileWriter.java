package org.owasp.astf.reporting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Writes report files readable only by their owner where the filesystem supports POSIX permissions. */
final class ReportFileWriter {

    private static final Logger logger = LogManager.getLogger(ReportFileWriter.class);

    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

    private ReportFileWriter() {
    }

    static void write(Path path, String content) throws IOException {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        Path dir = path.toAbsolutePath().getParent();

        // Write to an owner-only temporary file in the same directory and move it into place, so the
        // report is never readable by others, even when an existing file with wider permissions is
        // being replaced.
        Path tmp;
        try {
            tmp = Files.createTempFile(dir, ".astf-report-", ".tmp", PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        } catch (UnsupportedOperationException e) {
            Files.write(path, bytes); // non-POSIX filesystem: nothing to restrict
            return;
        } catch (IOException e) {
            writeInPlace(path, bytes, e);
            return;
        }
        try {
            Files.write(tmp, bytes);
            try {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /** Fallback when no temporary file can be created next to the report (for example a read-only directory). */
    private static void writeInPlace(Path path, byte[] bytes, IOException cause) throws IOException {
        logger.warn("Could not create a temporary file next to {} ({}); writing the report in place", path,
                cause.getMessage());
        if (!Files.exists(path)) {
            try {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
            } catch (UnsupportedOperationException | FileAlreadyExistsException e) {
                // created concurrently or non-POSIX: Files.write below handles it
            }
        }
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch (UnsupportedOperationException | IOException e) {
            logger.warn("Could not restrict permissions on report file {}: {}", path, e.getMessage());
        }
        Files.write(path, bytes);
    }
}
