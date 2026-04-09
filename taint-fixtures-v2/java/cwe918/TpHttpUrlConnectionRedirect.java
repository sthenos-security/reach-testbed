// Fixture: CWE-918 SSRF - Java
// VERDICT: TRUE_POSITIVE
// PATTERN: httpurlconnection_follow_redirects
// SOURCE: function_parameter (URL string)
// SINK: HttpURLConnection.openConnection
// TAINT_HOPS: 1
// NOTES: Follows redirects up to N times - initial URL may pass allowlist but redirect to internal
// REAL_WORLD: elastic/elasticsearch ingest-geoip/HttpClient.java
import java.net.*;
import java.io.*;

public class TpHttpUrlConnectionRedirect {
    private static final int MAX_REDIRECTS = 50;

    public InputStream fetchUrl(String url) throws Exception {
        int redirects = 0;
        while (redirects < MAX_REDIRECTS) {
            // VULNERABLE: follows redirects - initial URL may be safe but redirects to 169.254.169.254
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            int status = conn.getResponseCode();
            if (status == 301 || status == 302) {
                url = conn.getHeaderField("Location");
                redirects++;
                continue;
            }
            return conn.getInputStream();
        }
        throw new IOException("Too many redirects");
    }
}
