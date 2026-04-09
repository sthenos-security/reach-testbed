// Fixture: CWE-918 SSRF - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: url_constructor_blob_name_concat
// SOURCE: function_parameter (blob name)
// SINK: new URL(base, name).openStream()
// TAINT_HOPS: 1
// NOTES: Blob name used in URL constructor - can redirect to internal hosts
// REAL_WORLD: elastic/elasticsearch repository-url/URLBlobContainer.java
import java.net.*;
import java.io.*;

public class TpUrlConcatBlobName {
    private final URL basePath;

    public TpUrlConcatBlobName(URL basePath) {
        this.basePath = basePath;
    }

    public InputStream readBlob(String name) throws Exception {
        // VULNERABLE: blob name like "//evil.com/payload" overrides base URL host
        return new URL(basePath, name).openStream();
    }
}
