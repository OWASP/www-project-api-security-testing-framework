package org.owasp.astf.reporting;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/** Writes report files readable only by their owner where the filesystem supports POSIX permissions. */
final class ReportFileWriter {

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
        }
    }
}
