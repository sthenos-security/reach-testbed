// Fixture: code_patch · CWE-22 Path Traversal · Java
// VERDICT: TRUE_POSITIVE
// PATTERN: zip_extract_no_path_check
// SOURCE: zip_entry_name
// SINK: Files.copy
// TAINT_HOPS: 1
// NOTES: Classic zip-slip — no path validation after resolve
import java.io.*;
import java.nio.file.*;
import java.util.zip.*;
import java.util.Enumeration;

public class TpZipSlipNoValidation {
    public void extractUnsafe(File zipFile, File outputDir) throws Exception {
        try (ZipFile zip = new ZipFile(zipFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // VULNERABLE: no startsWith check — ../../etc/passwd escapes
                File outputFile = new File(outputDir, entry.getName());
                Files.copy(zip.getInputStream(entry), outputFile.toPath());
            }
        }
    }
}
