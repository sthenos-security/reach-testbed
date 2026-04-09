// Fixture: code_patch · CWE-22 Path Traversal · Java
// VERDICT: TRUE_NEGATIVE
// PATTERN: zip_extract_normalize_startswith
// SOURCE: zip_entry_name
// SINK: Files.copy
// TAINT_HOPS: 1
// NOTES: Elasticsearch-style — zip extraction with normalize + startsWith check
// REAL_WORLD: elastic/elasticsearch plugin extraction pattern
import java.io.*;
import java.nio.file.*;
import java.util.zip.*;
import java.util.Enumeration;

public class TnZipExtractValidated {
    public void extractSafe(File zipFile, File outputDir) throws Exception {
        Path baseDir = outputDir.toAbsolutePath().normalize();
        try (ZipFile zip = new ZipFile(zipFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                Path resolved = baseDir.resolve(entry.getName()).toAbsolutePath().normalize();
                if (!resolved.startsWith(baseDir)) {
                    throw new SecurityException("Zip entry outside dir: " + entry.getName());
                }
                Files.copy(zip.getInputStream(entry), resolved);
            }
        }
    }
}
